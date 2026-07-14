"""3.2.0 O5 Run Ledger — fail-closed validate (monotone seq + digest chain + budget) + DSSE round-trip.

Against best-of-many: aborted runs stay visible, a dropped/reordered run breaks the chain, runs never exceed
the declared budget. unittest-style.
"""
from __future__ import annotations

import base64
import copy
import json
import unittest

from proofbundle import dsse
from proofbundle.emit import generate_signer
from proofbundle.run_ledger import (
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    RunLedgerError,
    _rfc8785_bytes,
    build_run_ledger_statement,
    emit_run_ledger,
    link_runs,
    validate_run_ledger_predicate,
    verify_run_ledger,
)

_R1, _R2, _R3 = "1" * 64, "2" * 64, "3" * 64


def _pred(**over) -> dict:
    p = {
        "schemaVersion": "0.1.0",
        "studyId": "study-0001",
        "runBudget": 5,
        "runs": link_runs([_R1, _R2, _R3], ["completed", "aborted", "completed"]),
        "selectedSeq": 3,
        "nonClaims": [
            "does not prove the selected run is representative",
            "does not prove no run exists outside this ledger",
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


class TestRunLedgerValidate(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate_run_ledger_predicate(_pred()), [])

    def test_aborted_run_is_allowed_and_kept(self):
        # an aborted run in the middle is valid (visible, not dropped).
        p = _pred()
        self.assertEqual(p["runs"][1]["status"], "aborted")
        self.assertEqual(validate_run_ledger_predicate(p), [])

    def test_nonclaims_mandatory(self):
        p = _pred()
        del p["nonClaims"]
        self.assertTrue(any("nonClaims" in e for e in validate_run_ledger_predicate(p)))

    def test_seq_gap_fails(self):
        p = _pred()
        p["runs"][2]["seq"] = 4  # gap: 1,2,4
        self.assertTrue(any("monotone" in e for e in validate_run_ledger_predicate(p)))

    def test_broken_chain_fails(self):
        # tamper run[2].prevDigest so it no longer equals run[1].resultDigest → chain broken (dropped run).
        p = _pred()
        p["runs"][2]["prevDigest"] = {"sha256": "f" * 64}
        errs = validate_run_ledger_predicate(p)
        self.assertTrue(any("chain is broken" in e for e in errs), errs)

    def test_first_prevdigest_must_be_null(self):
        p = _pred()
        p["runs"][0]["prevDigest"] = {"sha256": _R1}
        self.assertTrue(any("must be null" in e for e in validate_run_ledger_predicate(p)))

    def test_over_budget_fails(self):
        p = _pred(runBudget=2)  # 3 runs > budget 2
        self.assertTrue(any("runBudget" in e for e in validate_run_ledger_predicate(p)))

    def test_bad_run_status_fails(self):
        p = _pred()
        p["runs"][0]["status"] = "queued"
        self.assertTrue(any("status" in e for e in validate_run_ledger_predicate(p)))

    def test_selected_seq_out_of_range_fails(self):
        p = _pred(selectedSeq=9)
        self.assertTrue(any("selectedSeq" in e for e in validate_run_ledger_predicate(p)))

    def test_link_runs_rejects_bad_digest(self):
        with self.assertRaises(RunLedgerError):
            link_runs(["short"])

    def test_link_runs_rejects_status_mismatch_and_bad_status(self):
        # link_runs is the helper users build signed ledgers with — a regression to silent acceptance would
        # put malformed chain links into a SIGNED ledger. Statuses must match the digest count and be valid.
        with self.assertRaises(RunLedgerError):
            link_runs([_R1, _R2], ["completed"])     # statuses length != digests length
        with self.assertRaises(RunLedgerError):
            link_runs([_R1], ["bogus"])              # invalid status value

    def test_emit_rejects_invalid(self):
        s, _ = _keys()
        with self.assertRaises(RunLedgerError):
            emit_run_ledger(_pred(runBudget=1), s)


class TestRunLedgerVerify(unittest.TestCase):
    def test_roundtrip_green(self):
        s, pub = _keys()
        env = emit_run_ledger(_pred(), s)
        r = verify_run_ledger(env, pub, strict=True)
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["chain_intact"] and r["within_budget"])

    def test_tamper_breaks_crypto(self):
        s, pub = _keys()
        env = emit_run_ledger(_pred(), s)
        forged = _repayload(env, build_run_ledger_statement(_pred(studyId="X")))
        r = verify_run_ledger(forged, pub)
        self.assertFalse(r["ok"])
        self.assertFalse(r["crypto_ok"])

    def test_wrong_key_fails(self):
        s, _ = _keys()
        _, other = _keys()
        env = emit_run_ledger(_pred(), s)
        self.assertFalse(verify_run_ledger(env, other)["ok"])

    def test_predicate_type_confusion_fails(self):
        s, pub = _keys()
        stmt = build_run_ledger_statement(_pred())
        stmt["predicateType"] = "https://in-toto.io/attestation/vulns"
        env = dsse.sign_envelope(_rfc8785_bytes(stmt), s, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        r = verify_run_ledger(env, pub)
        self.assertFalse(r["predicate_type_ok"])
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
