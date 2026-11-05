"""Approvals are honoured at most once: Section 4 of draft-gruszka-audit-decision-receipts-07, checked against a
consumption state the relying party supplies.

Finding B4 of the list of 2 November 2026 (vectors F10, F13, F71, F77, F90), Owner choice A on OA-616feb8f26
(2026-11-05T21:38:26Z): ``decision verify`` reads a given consumption state read-only and refuses with exit 3. proofbundle
never writes the state and never marks an approval as consumed; item 3 (mark durably before the action runs) stays the
relying party's duty. An OK says only that the approval identity is not in the state given.

- the consumption state (``consumed_state`` / ``--consumed PATH``): a JSON array of approval identities, or an object
  of generations (current, rotated, archived, ...) each an array of identities. An identity is approvalId, actionDigest
  and session (item 2). An identity in any generation refuses (items 1 and 4); a state that does not parse or holds a
  malformed entry is no complete view and refuses (item 5).
- received copies (``received_copies`` / ``--received PATH``): a JSON array of approval records; among the copies with
  the same identity, and the supplied record, T must be strictly earlier than the earliest validUntil (item 2).
- Section 4 applies after Case 1 holds: without ``case="approval"`` and its record, a state given is refused.

unittest-style like tests/test_decision_cli.py."""
from __future__ import annotations

import base64
import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from proofbundle.cli import main
from proofbundle.decision import _rfc8785_bytes, emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer

import test_decision_case_checks_of_section_3_3 as _fall1

T_GUT = _fall1.T_GUT


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = main(argv)
        except SystemExit as exc:
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


def _kennung(a):
    return {"approvalId": a["approvalId"], "actionDigest": a["actionDigest"], "session": a["session"]}


def _j(wert) -> bytes:
    return json.dumps(wert).encode()


class _Basis(unittest.TestCase):
    def setUp(self):
        self.s = generate_signer()
        self.pub = self.s.public_key().public_bytes_raw()
        self.a = _fall1._freigabe()
        self.ab = _rfc8785_bytes(self.a)
        self.env = emit_decision_receipt(_fall1._entscheidung(self.ab), self.s)

    def _v(self, consumed=None, received=None, case="approval", ab=None, now=T_GUT):
        return verify_decision_receipt(self.env, self.pub, strict=True, case=case,
                                       approval_record=self.ab if ab is None else ab, consumed_state=consumed,
                                       received_copies=received, now=now)


class TestConsumption(_Basis):
    def test_identity_not_consumed_holds(self):
        r = self._v(consumed=_j([]))
        self.assertIs(r["consumption_ok"], True, r["errors"])
        self.assertTrue(r["ok"], r["errors"])

    def test_without_a_state_nothing_is_said(self):
        r = self._v()
        self.assertIsNone(r["consumption_ok"])
        self.assertTrue(r["ok"], r["errors"])

    def test_f10_f77_consumed_in_current(self):
        r = self._v(consumed=_j([_kennung(self.a)]))
        self.assertIs(r["consumption_ok"], False)
        self.assertFalse(r["ok"])
        self.assertTrue(any("already consumed" in e for e in r["errors"]), r["errors"])

    def test_f13_consumed_in_a_rotated_generation(self):
        for generation in ("rotated", "archived", "compacted"):
            with self.subTest(generation=generation):
                r = self._v(consumed=_j({"current": [], generation: [_kennung(self.a)]}))
                self.assertIs(r["consumption_ok"], False)

    def test_copy_with_other_metadata_is_the_same_approval(self):
        # Item 2: the identity is approvalId, actionDigest and session, not the bytes of one copy.
        andere = dict(_kennung(self.a))
        r = self._v(consumed=_j([andere]))
        self.assertIs(r["consumption_ok"], False)

    def test_other_identity_does_not_refuse(self):
        r = self._v(consumed=_j([dict(_kennung(self.a), session="sess-other")]))
        self.assertIs(r["consumption_ok"], True, r["errors"])

    def test_f71_state_that_does_not_parse_refuses(self):
        for roh in (b"[{", b"", b"null", b'{"current": 5}', b'[{"approvalId": "x"}]', b'[1]'):
            with self.subTest(state=roh):
                r = self._v(consumed=roh)
                self.assertIs(r["consumption_ok"], False)

    def test_f90_earliest_valid_until_of_received_copies(self):
        kopie = dict(self.a, validUntil="2026-07-16T09:00:30Z")   # earlier than T 09:01:00Z
        r = self._v(consumed=_j([]), received=_j([kopie]))
        self.assertIs(r["consumption_ok"], False)
        self.assertTrue(any("earliest validUntil" in e for e in r["errors"]), r["errors"])

    def test_received_copy_of_another_identity_does_not_bound(self):
        kopie = dict(self.a, session="sess-other", validUntil="2026-07-16T09:00:30Z")
        r = self._v(consumed=_j([]), received=_j([kopie]))
        self.assertIs(r["consumption_ok"], True, r["errors"])

    def test_received_without_state_is_refused(self):
        r = self._v(received=_j([self.a]))
        self.assertIs(r["consumption_ok"], False)

    def test_state_without_the_approval_case_is_refused(self):
        r = verify_decision_receipt(self.env, self.pub, strict=True, consumed_state=_j([]), now=T_GUT)
        self.assertIs(r["consumption_ok"], False)
        self.assertFalse(r["ok"])

    def test_state_is_not_judged_when_case_1_fails(self):
        r = self._v(consumed=_j([]), ab=_rfc8785_bytes(dict(self.a, session="x")))
        self.assertIs(r["case_ok"], False)
        self.assertIsNone(r["consumption_ok"])


class TestConsumptionCli(_Basis):
    def setUp(self):
        super().setUp()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.rec = self.tmp / "d.json"
        self.rec.write_text(json.dumps(self.env), encoding="utf-8")
        self.approval = self.tmp / "a.json"
        self.approval.write_bytes(self.ab)

    def _datei(self, name, wert):
        p = self.tmp / name
        p.write_bytes(wert)
        return str(p)

    def _cli(self, *extra):
        return _run(["decision", "verify", str(self.rec), "--pub", base64.b64encode(self.pub).decode(), "--strict",
                     "--verification-time", "2026-07-16T09:01:00Z", "--case", "approval",
                     "--approval", str(self.approval), *extra])

    def test_cli_not_consumed_exit_0(self):
        rc, out, err = self._cli("--consumed", self._datei("c.json", _j([])))
        self.assertEqual(rc, 0, err)
        self.assertIn("CONSUMPTION: NOT CONSUMED (in the state given)", out)

    def test_cli_consumed_exit_3(self):
        rc, out, _ = self._cli("--consumed", self._datei("c.json", _j([_kennung(self.a)])))
        self.assertEqual(rc, 3)
        self.assertIn("CONSUMPTION: REFUSE", out)

    def test_cli_unreadable_state_exit_3(self):
        rc, _, _ = self._cli("--consumed", self._datei("c.json", b"[{"))
        self.assertEqual(rc, 3)

    def test_cli_received_bound_exit_3(self):
        kopie = dict(self.a, validUntil="2026-07-16T09:00:30Z")
        rc, _, _ = self._cli("--consumed", self._datei("c.json", _j([])), "--received", self._datei("r.json", _j([kopie])))
        self.assertEqual(rc, 3)

    def test_cli_empty_values_exit_2(self):
        for extra in (["--consumed", ""], ["--consumed", self._datei("c.json", _j([])), "--received", ""]):
            with self.subTest(extra=extra):
                rc, _, _ = self._cli(*extra)
                self.assertEqual(rc, 2)

    def test_cli_without_state_unchanged(self):
        rc, out, _ = self._cli()
        self.assertEqual(rc, 0)
        self.assertNotIn("CONSUMPTION:", out)


if __name__ == "__main__":
    unittest.main()
