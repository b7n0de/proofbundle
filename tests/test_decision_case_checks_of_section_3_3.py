"""The checks per case of Section 3.3 of draft-gruszka-audit-decision-receipts-07.

Finding B3 of the list of 2 November 2026 (vectors F9 and F14), and the vectors of B14 with the same cause (F17, F40 to
F54, F74, F76, F89). Measured on main 6f5955d1: proofbundle chose no case and took no approval record, so a receipt
for a human approval passed with the wrong verdict, without user_approval, without or with a broken approval record,
and with violated bounds; a declined receipt passed with ESCALATE or an executed outcome; and an outcome bound to an
ESCALATE decision, or one with status failed, passed as an executed action. The relying party chooses the case, the
receipt never does (Section 3.1).

- Case 1, approval (``decision verify --case approval --approval PATH``): verdict ALLOW, reasonCodes contain
  user_approval, inputSnapshot holds exactly one entry named "approval record", the approval record bytes A are
  supplied, hash to that entry's digest and are their own RFC 8785 form; A holds approvalId, approver and session
  (non-empty strings), actionDigest (a digest equal to parametersDigest), approvedAt and validUntil (timestamps of
  the draft's form); approver equals principal.id; approvedAt <= decidedAt <= T < validity.expiresAt <= validUntil.
- Case 2, declined (``--case declined``): verdict DENY or REFUSE; an actionOutcome has status notAttempted, blocked
  or refused, and performedAt and outcomeRef absent or null.
- Case 3, executed (``outcome verify --case executed`` with ``--decision``): the decision's verdict is ALLOW, and the
  outcome passes Section 3.4 and has status executed.

unittest-style like tests/test_decision_cli.py."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from proofbundle.cli import main
from proofbundle.decision import _rfc8785_bytes, emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
ACTION = b'{"merge":"pull/4471"}\n'
T_GUT = 1784192460            # 2026-07-16T09:01:00Z, after decidedAt and before expiresAt below
PRINCIPAL = "workload://example/ci-release"


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = main(argv)
        except SystemExit as exc:
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


def _freigabe(**over):
    a = {"approvalId": "appr-0001", "approver": PRINCIPAL, "session": "sess-1",
         "actionDigest": {"sha256": hashlib.sha256(ACTION).hexdigest()},
         "approvedAt": "2026-07-16T08:59:00Z", "validUntil": "2026-07-16T09:10:00Z"}
    for k, v in over.items():
        if v is _WEG:
            a.pop(k, None)
        else:
            a[k] = v
    return a


_WEG = object()


def _bytes(a):
    return _rfc8785_bytes(a)


def _entscheidung(approval_bytes=None, verdict="ALLOW", reason=("user_approval",), eintraege=1, **over):
    p = json.loads((EXAMPLES / "decision_receipt_allow.json").read_text(encoding="utf-8"))
    p["proposedAction"]["parametersDigest"] = {"sha256": hashlib.sha256(ACTION).hexdigest()}
    p["principal"] = {"id": PRINCIPAL}
    p["decidedAt"] = "2026-07-16T09:00:00Z"
    p["validity"] = {"audience": ["rp"], "nonce": "n-1", "expiresAt": "2026-07-16T09:05:00Z"}
    p["decision"]["verdict"] = verdict
    p["decision"]["reasonCodes"] = list(reason)
    ab = approval_bytes if approval_bytes is not None else _bytes(_freigabe())
    eintrag = {"name": "approval record", "digest": {"sha256": hashlib.sha256(ab).hexdigest()},
               "mediaType": "application/json"}
    p["inputSnapshot"] = [x for x in p["inputSnapshot"] if x.get("name") != "approval record"] + [eintrag] * eintraege
    p.pop("actionOutcome", None)
    p.update(over)
    return p


class _Basis(unittest.TestCase):
    def setUp(self):
        self.s = generate_signer()
        self.pub = self.s.public_key().public_bytes_raw()

    def _env(self, p):
        return emit_decision_receipt(p, self.s)

    def _case1(self, p, ab, now=T_GUT):
        return verify_decision_receipt(self._env(p), self.pub, strict=True, case="approval", approval_record=ab,
                                       now=now)


class TestCase1Approval(_Basis):
    def test_good_approval_holds(self):
        ab = _bytes(_freigabe())
        r = self._case1(_entscheidung(ab), ab)
        self.assertIs(r["case_ok"], True, r["errors"])
        self.assertTrue(r["ok"], r["errors"])

    def test_without_a_case_nothing_changes(self):
        ab = _bytes(_freigabe())
        r = verify_decision_receipt(self._env(_entscheidung(ab)), self.pub, strict=True, now=T_GUT)
        self.assertIsNone(r["case_ok"])
        self.assertTrue(r["ok"], r["errors"])

    def _faellt(self, p, ab, now=T_GUT):
        r = self._case1(p, ab, now)
        self.assertIs(r["case_ok"], False, r["errors"])
        self.assertFalse(r["ok"])
        return r

    def test_f40_verdict_other_than_allow(self):
        ab = _bytes(_freigabe())
        self._faellt(_entscheidung(ab, verdict="ESCALATE"), ab)

    def test_f14_reason_codes_lack_user_approval(self):
        ab = _bytes(_freigabe())
        self._faellt(_entscheidung(ab, reason=("policy.satisfied",)), ab)

    def test_f41_two_approval_records(self):
        ab = _bytes(_freigabe())
        self._faellt(_entscheidung(ab, eintraege=2), ab)

    def test_f89_no_approval_record(self):
        ab = _bytes(_freigabe())
        self._faellt(_entscheidung(ab, eintraege=0), ab)

    def test_f42_approval_bytes_not_supplied(self):
        ab = _bytes(_freigabe())
        self._faellt(_entscheidung(ab), None)

    def test_f43_approval_bytes_do_not_hash(self):
        ab = _bytes(_freigabe())
        self._faellt(_entscheidung(ab), _bytes(_freigabe(session="sess-2")))

    def test_f44_approval_not_its_own_rfc8785_form(self):
        roh = json.dumps(_freigabe(), indent=1).encode()
        self._faellt(_entscheidung(roh), roh)

    def test_f45_approval_lacks_valid_until(self):
        ab = _bytes(_freigabe(validUntil=_WEG))
        self._faellt(_entscheidung(ab), ab)

    def test_f46_session_not_a_non_empty_string(self):
        for wert in ("", 7):
            with self.subTest(session=wert):
                ab = _bytes(_freigabe(session=wert))
                self._faellt(_entscheidung(ab), ab)

    def test_f47_action_digest_not_a_digest(self):
        ab = _bytes(_freigabe(actionDigest={"sha256": "XYZ"}))
        self._faellt(_entscheidung(ab), ab)

    def test_f48_approval_names_other_action_bytes(self):
        ab = _bytes(_freigabe(actionDigest={"sha256": hashlib.sha256(b"other").hexdigest()}))
        self._faellt(_entscheidung(ab), ab)

    def test_f49_approver_is_not_the_principal(self):
        ab = _bytes(_freigabe(approver="someone://else"))
        self._faellt(_entscheidung(ab), ab)

    def test_f50_f76_timestamps_not_of_the_drafts_form(self):
        for feld, wert in (("approvedAt", "2026-07-16 08:59:00Z"), ("validUntil", "2026-07-16T09:10:00+00:00"),
                           ("approvedAt", "2026-07-16T08:59:00.0000001Z")):
            with self.subTest(feld=feld, wert=wert):
                ab = _bytes(_freigabe(**{feld: wert}))
                self._faellt(_entscheidung(ab), ab)

    def test_f9_f74_bounds(self):
        ab_spaet = _bytes(_freigabe(approvedAt="2026-07-16T09:00:00.000001Z"))   # after decidedAt
        self._faellt(_entscheidung(ab_spaet), ab_spaet)
        ab_kurz = _bytes(_freigabe(validUntil="2026-07-16T09:04:59.999999Z"))   # before expiresAt
        self._faellt(_entscheidung(ab_kurz), ab_kurz)
        ab = _bytes(_freigabe())
        self._faellt(_entscheidung(ab), ab, now=1784192700)                     # T == expiresAt 09:05:00Z
        self._faellt(_entscheidung(ab), ab, now=1784192399)                     # T before decidedAt

    def test_bounds_hold_at_their_edges(self):
        ab = _bytes(_freigabe(approvedAt="2026-07-16T09:00:00Z", validUntil="2026-07-16T09:05:00Z"))
        r = self._case1(_entscheidung(ab), ab, now=1784192400)                 # T == decidedAt
        self.assertIs(r["case_ok"], True, r["errors"])


class TestCase2Declined(_Basis):
    def _case2(self, p):
        return verify_decision_receipt(self._env(p), self.pub, strict=True, case="declined", now=T_GUT)

    def test_deny_and_refuse_hold(self):
        for verdict in ("DENY", "REFUSE"):
            with self.subTest(verdict=verdict):
                r = self._case2(_entscheidung(verdict=verdict, reason=("risk.boundary.exceeded",)))
                self.assertIs(r["case_ok"], True, r["errors"])

    def test_f51_verdict_escalate(self):
        r = self._case2(_entscheidung(verdict="ESCALATE", reason=("x",)))
        self.assertIs(r["case_ok"], False)
        self.assertFalse(r["ok"])

    def test_f52_outcome_status_executed(self):
        p = _entscheidung(verdict="DENY", reason=("x",), actionOutcome={"status": "executed", "performedAt": None,
                                                                          "outcomeRef": None})
        self.assertIs(self._case2(p)["case_ok"], False)

    def test_f53_outcome_names_a_performance(self):
        p = _entscheidung(verdict="DENY", reason=("x",),
                          actionOutcome={"status": "blocked", "performedAt": "2026-07-16T09:01:00Z", "outcomeRef": None})
        self.assertIs(self._case2(p)["case_ok"], False)

    def test_declined_outcome_without_performance_holds(self):
        p = _entscheidung(verdict="REFUSE", reason=("x",),
                          actionOutcome={"status": "refused", "performedAt": None, "outcomeRef": None})
        self.assertIs(self._case2(p)["case_ok"], True)


class TestUnknownCase(_Basis):
    def test_unknown_case_fails_closed(self):
        r = verify_decision_receipt(self._env(_entscheidung()), self.pub, strict=True, case="executed", now=T_GUT)
        self.assertIs(r["case_ok"], False)
        self.assertFalse(r["ok"])


class TestCase3Executed(unittest.TestCase):
    """Case 3 on the outcome path: the decision's verdict ALLOW, and the outcome has status executed."""

    def setUp(self):
        self.ds, self.os_ = generate_signer(), generate_signer()
        self.dpub = self.ds.public_key().public_bytes_raw()
        self.opub = self.os_.public_key().public_bytes_raw()

    def _paar(self, verdict="ALLOW", status="executed"):
        dec = emit_decision_receipt(_entscheidung(verdict=verdict, reason=("policy.satisfied",)), self.ds)
        wurzel = hashlib.sha256(base64.b64decode(dec["payload"])).hexdigest()
        out = emit_outcome_receipt({
            "schemaVersion": "0.1.0", "outcomeId": "o-1", "decisionRef": {"sha256": wurzel},
            "executor": {"id": "forge:agent-42-bot"},
            "requestedActionDigest": {"sha256": hashlib.sha256(ACTION).hexdigest()}, "status": status,
            "performedAt": "2026-07-16T09:01:00Z", "effectDigest": {"sha256": "e" * 64}}, self.os_)
        return dec, out

    def _case3(self, dec, out, **kw):
        return verify_outcome_receipt(out, self.opub, strict=True, decision_envelope=dec,
                                      decision_public_key=self.dpub, case="executed", **kw)

    def test_executed_holds(self):
        r = self._case3(*self._paar())
        self.assertIs(r["case_ok"], True, r["errors"])
        self.assertTrue(r["ok"], r["errors"])

    def test_f17_decision_escalate(self):
        r = self._case3(*self._paar(verdict="ESCALATE"))
        self.assertIs(r["case_ok"], False)
        self.assertFalse(r["ok"])

    def test_f54_outcome_failed(self):
        r = self._case3(*self._paar(status="failed"))
        self.assertIs(r["case_ok"], False)
        self.assertFalse(r["ok"])

    def test_case_executed_needs_the_decision(self):
        _, out = self._paar()
        r = verify_outcome_receipt(out, self.opub, strict=True, case="executed")
        self.assertIs(r["case_ok"], False)

    def test_without_a_case_nothing_changes(self):
        dec, out = self._paar(status="failed")
        r = verify_outcome_receipt(out, self.opub, strict=True, decision_envelope=dec, decision_public_key=self.dpub)
        self.assertIsNone(r["case_ok"])


class TestCaseCli(_Basis):
    def setUp(self):
        super().setUp()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ab = _bytes(_freigabe())
        self.approval = self.tmp / "approval.json"
        self.approval.write_bytes(self.ab)

    def _cli(self, p, *extra):
        rec = self.tmp / "d.json"
        rec.write_text(json.dumps(self._env(p)), encoding="utf-8")
        return _run(["decision", "verify", str(rec), "--pub", base64.b64encode(self.pub).decode(), "--strict",
                     "--verification-time", "2026-07-16T09:01:00Z", *extra])

    def test_cli_case_approval_holds_exit_0(self):
        rc, out, err = self._cli(_entscheidung(self.ab), "--case", "approval", "--approval", str(self.approval))
        self.assertEqual(rc, 0, err)
        self.assertIn("CASE: OK (approval)", out)

    def test_cli_case_approval_fails_exit_2(self):
        rc, out, _ = self._cli(_entscheidung(self.ab, reason=("policy.satisfied",)), "--case", "approval",
                               "--approval", str(self.approval))
        self.assertEqual(rc, 2)
        self.assertIn("CASE: FAIL (approval)", out)

    def test_cli_case_approval_without_record_exit_2(self):
        rc, _, _ = self._cli(_entscheidung(self.ab), "--case", "approval")
        self.assertEqual(rc, 2)

    def test_cli_approval_without_case_exit_2(self):
        rc, _, _ = self._cli(_entscheidung(self.ab), "--approval", str(self.approval))
        self.assertEqual(rc, 2)

    def test_cli_case_declined_exit_0_and_2(self):
        rc, _, _ = self._cli(_entscheidung(verdict="DENY", reason=("x",)), "--case", "declined")
        self.assertEqual(rc, 0)
        rc, _, _ = self._cli(_entscheidung(verdict="ESCALATE", reason=("x",)), "--case", "declined")
        self.assertEqual(rc, 2)

    def test_cli_unknown_case_exit_2(self):
        rc, _, _ = self._cli(_entscheidung(self.ab), "--case", "executed")
        self.assertEqual(rc, 2)

    def test_cli_without_case_unchanged(self):
        rc, out, _ = self._cli(_entscheidung(self.ab))
        self.assertEqual(rc, 0)
        self.assertNotIn("CASE:", out)

    def test_cli_empty_approval_value_exit_2(self):
        rc, _, _ = self._cli(_entscheidung(self.ab), "--case", "approval", "--approval", "")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
