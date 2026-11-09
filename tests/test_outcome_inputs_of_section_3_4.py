"""The inputs Section 3.4 of draft-gruszka-audit-decision-receipts-07 gives the verifier of an outcome receipt.

Finding B2 of the list of 2 November 2026 (vectors F6, F7 and F8 of the draft's test package). Measured on main
6f5955d1: ``outcome verify`` took neither the expected ``executor.id`` (step 5), nor effect bytes (step 6), nor the
decision receipt the outcome is bound to (steps 4, 5 and 7), so it could not fail F6, F7 or F8 and ended with
exit 0. These tests ask for the inputs (``expected_executor_id``, ``effect_bytes``, ``decision_envelope`` with
``decision_public_key`` in the library; ``--executor-id``, ``--effect``, ``--decision`` with ``--decision-pub`` on
the command line) and for the verdicts the draft gives:

- step 4: ``decisionRef.sha256`` equals the content root R of the decision receipt, and ``requestedActionDigest``
  equals its ``proposedAction.parametersDigest``;
- step 5: ``executor.id`` equals the expected identifier; the outcome key differs from the decision key, and
  ``executor.id`` differs from ``decisionMaker.id``;
- step 6: where effect bytes are supplied, ``effectDigest`` is present and their SHA-256 equals it;
- step 7: ``decidedAt <= performedAt < validity.expiresAt`` of the decision, fractions padded to six digits.

The first sentence of step 6 (an executed outcome without effectDigest) is not here: proofbundle reports it as
``execution_proven`` False with a warning, and turning that into a failure belongs to B14 (F68).

unittest-style like tests/test_outcome_verify.py."""
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
from proofbundle.decision import emit_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
ACTION = b'{"publish":"release-4471"}\n'
EFFECT = b'{"published":"release-4471","url":"https://example.org/r/4471"}\n'
EXECUTOR = "forge:agent-42-bot"
#: The decisionMaker.id of examples/decision_receipt_allow.json, the identifier the relying party expects (3.1).
MAKER = "https://example.org/decision-platform/proofbundle-gate/v1"
#: The evaluation time T the relying party supplies (3.1): 2026-07-09T11:17:00Z, inside the decision's validity.
T_IM_FENSTER = 1783595820
T_TEXT = "2026-07-09T11:17:00Z"


def _run(argv):
    """cli.main(argv) as (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = main(argv)
        except SystemExit as exc:
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


def _decision_predicate():
    p = json.loads((EXAMPLES / "decision_receipt_allow.json").read_text(encoding="utf-8"))
    p["proposedAction"]["parametersDigest"] = {"sha256": hashlib.sha256(ACTION).hexdigest()}
    p["decidedAt"] = "2026-07-09T11:15:00Z"
    p["validity"] = {"audience": ["observer-1"], "nonce": "dec-0003", "expiresAt": "2026-07-09T11:20:00Z"}
    return p


def _content_root(env):
    return hashlib.sha256(base64.b64decode(env["payload"])).hexdigest()


def _outcome_predicate(decision_env, **over):
    p = {
        "schemaVersion": "0.1.0",
        "outcomeId": "outcome-0003",
        "decisionRef": {"sha256": _content_root(decision_env)},
        "executor": {"id": EXECUTOR},
        "requestedActionDigest": {"sha256": hashlib.sha256(ACTION).hexdigest()},
        "status": "executed",
        "performedAt": "2026-07-09T11:16:00Z",
        "effectDigest": {"sha256": hashlib.sha256(EFFECT).hexdigest()},
    }
    p.update(over)
    return p


class _Paar(unittest.TestCase):
    def setUp(self):
        self.ds, self.os_ = generate_signer(), generate_signer()
        self.dpub = self.ds.public_key().public_bytes_raw()
        self.opub = self.os_.public_key().public_bytes_raw()
        self.dec = emit_decision_receipt(_decision_predicate(), self.ds)

    def _out(self, **over):
        return emit_outcome_receipt(_outcome_predicate(self.dec, **over), self.os_)

    def _verify(self, env, **kw):
        args = {"expected_executor_id": EXECUTOR, "effect_bytes": EFFECT, "decision_envelope": self.dec,
                "decision_public_key": self.dpub, "decision_maker_id": MAKER, "now": T_IM_FENSTER}
        args.update(kw)
        return verify_outcome_receipt(env, self.opub, strict=True, **args)


class TestSection34Library(_Paar):
    def test_all_inputs_hold(self):
        r = self._verify(self._out())
        self.assertIs(r["executor_id_ok"], True)
        self.assertIs(r["effect_bytes_ok"], True)
        self.assertIs(r["bound_decision_ok"], True)
        self.assertTrue(r["ok"], r["errors"])

    def test_without_the_new_inputs_nothing_changes(self):
        r = verify_outcome_receipt(self._out(), self.opub, strict=True)
        self.assertIsNone(r["executor_id_ok"])
        self.assertIsNone(r["effect_bytes_ok"])
        self.assertIsNone(r["bound_decision_ok"])
        self.assertTrue(r["ok"], r["errors"])

    # step 5, F6
    def test_other_executor_fails(self):
        r = self._verify(self._out(executor={"id": "forge:another-actor"}))
        self.assertIs(r["executor_id_ok"], False)
        self.assertFalse(r["ok"])

    def test_executor_id_compared_exactly(self):
        for nah in (EXECUTOR + " ", EXECUTOR.upper(), EXECUTOR[:-1], " " + EXECUTOR):
            with self.subTest(expected=nah):
                self.assertIs(self._verify(self._out(), expected_executor_id=nah)["executor_id_ok"], False)

    # step 6, F7 and F69
    def test_effect_bytes_without_effect_digest_fail(self):
        p = _outcome_predicate(self.dec)
        del p["effectDigest"]
        r = self._verify(emit_outcome_receipt(p, self.os_))
        self.assertIs(r["effect_bytes_ok"], False)
        self.assertFalse(r["ok"])

    def test_other_effect_bytes_fail(self):
        r = self._verify(self._out(), effect_bytes=EFFECT + b" ")
        self.assertIs(r["effect_bytes_ok"], False)
        self.assertFalse(r["ok"])

    def test_effect_bytes_checked_whatever_the_status(self):
        r = self._verify(self._out(status="failed"), effect_bytes=b"other")
        self.assertIs(r["effect_bytes_ok"], False)

    # step 4, F64 and the content root
    def test_requested_action_other_than_the_decision_fails(self):
        r = self._verify(self._out(requestedActionDigest={"sha256": hashlib.sha256(b"x").hexdigest()}))
        self.assertIs(r["bound_decision_ok"], False)
        self.assertFalse(r["ok"])

    def test_decision_ref_other_than_the_content_root_fails(self):
        r = self._verify(self._out(decisionRef={"sha256": "a" * 64}))
        self.assertIs(r["bound_decision_ok"], False)
        self.assertFalse(r["ok"])

    # step 7, F8, F70 and the fraction rule
    def test_performed_before_the_decision_fails(self):
        r = self._verify(self._out(performedAt="2026-07-09T11:14:59Z"))
        self.assertIs(r["bound_decision_ok"], False)

    def test_performed_at_expiry_fails(self):
        r = self._verify(self._out(performedAt="2026-07-09T11:20:00Z"))
        self.assertIs(r["bound_decision_ok"], False)

    def test_performed_at_decision_time_passes(self):
        self.assertIs(self._verify(self._out(performedAt="2026-07-09T11:15:00Z"))["bound_decision_ok"], True)

    def test_fractions_are_padded(self):
        self.assertIs(self._verify(self._out(performedAt="2026-07-09T11:19:59.999999Z"))["bound_decision_ok"], True)
        self.assertIs(self._verify(self._out(performedAt="2026-07-09T11:14:59.9Z"))["bound_decision_ok"], False)

    # step 5, separation against the decision
    def test_same_key_for_decision_and_outcome_fails(self):
        env = emit_outcome_receipt(_outcome_predicate(self.dec), self.ds)
        r = verify_outcome_receipt(env, self.dpub, strict=True, expected_executor_id=EXECUTOR, effect_bytes=EFFECT,
                                   decision_envelope=self.dec, decision_public_key=self.dpub,
                                   decision_maker_id=MAKER, now=T_IM_FENSTER)
        self.assertIs(r["bound_decision_ok"], False)
        self.assertFalse(r["ok"])

    def test_executor_is_the_decision_maker_fails(self):
        maker = _decision_predicate()["decisionMaker"]["id"]
        r = self._verify(self._out(executor={"id": maker}), expected_executor_id=maker)
        self.assertIs(r["bound_decision_ok"], False)
        self.assertFalse(r["ok"])

    # the decision receipt itself
    def test_decision_under_another_key_fails(self):
        other = generate_signer().public_key().public_bytes_raw()
        r = self._verify(self._out(), decision_public_key=other)
        self.assertIs(r["bound_decision_ok"], False)
        self.assertFalse(r["ok"])

    def test_decision_without_its_key_fails(self):
        r = self._verify(self._out(), decision_public_key=None)
        self.assertIs(r["bound_decision_ok"], False)
        self.assertFalse(r["ok"])

    def test_decision_without_validity_fails_the_window(self):
        p = _decision_predicate()
        del p["validity"]
        dec = emit_decision_receipt(p, self.ds)
        env = emit_outcome_receipt(_outcome_predicate(dec), self.os_)
        r = self._verify(env, decision_envelope=dec)
        self.assertIs(r["bound_decision_ok"], False)

    def test_not_judged_over_unauthenticated_bytes(self):
        other = generate_signer().public_key().public_bytes_raw()
        r = verify_outcome_receipt(self._out(), other, strict=True, expected_executor_id=EXECUTOR,
                                   effect_bytes=EFFECT, decision_envelope=self.dec, decision_public_key=self.dpub,
                                   decision_maker_id=MAKER, now=T_IM_FENSTER)
        self.assertFalse(r["crypto_ok"])
        self.assertIsNone(r["executor_id_ok"])
        self.assertIsNone(r["effect_bytes_ok"])
        self.assertIsNone(r["bound_decision_ok"])

    # step 4: the decision receipt passes decision verify, its whole verdict, at the relying party's T (3.1) and under the
    # decisionMaker.id the relying party expects (step 8 of 3.2). Measured at e200c107: an expired decision and one
    # signed for another decision maker both gave bound_decision_ok True, because only signature, structure,
    # predicate type and derived subject of the decision's verdict were read.
    def test_an_expired_decision_does_not_bind(self):
        for now in (1783596000, 1783596001):              # T == validity.expiresAt 11:20:00Z, and one second after
            with self.subTest(now=now):
                r = self._verify(self._out(), now=now)
                self.assertIs(r["bound_decision_ok"], False)
                self.assertFalse(r["ok"])

    def test_without_t_the_decision_is_judged_at_the_wall_clock(self):
        # The fixture's decision expired on 2026-07-09; at the wall clock it no longer passes decision verify.
        r = self._verify(self._out(), now=None)
        self.assertIs(r["bound_decision_ok"], False)

    def test_a_decision_of_another_decision_maker_does_not_bind(self):
        p = _decision_predicate()
        p["decisionMaker"]["id"] = "intruder-id"
        dec = emit_decision_receipt(p, self.ds)
        env = emit_outcome_receipt(_outcome_predicate(dec), self.os_)
        r = self._verify(env, decision_envelope=dec)
        self.assertIs(r["bound_decision_ok"], False)
        self.assertFalse(r["ok"])

    def test_the_bound_decision_maker_is_compared_exactly(self):
        """The near-miss corpus of tests/_beinahe_treffer.py over the expected decisionMaker.id of the bound decision
        (step 8 of Section 3.2, through Section 3.4): at the comparison itself and through the public argument,
        which passes the value on, so neither a prefix, a case fold, a strip nor a normal form binds."""
        from _beinahe_treffer import pruefe_exakt  # noqa: PLC0415
        from proofbundle.outcome import _gebundene_entscheidung  # noqa: PLC0415
        pred = _outcome_predicate(self.dec)
        pruefe_exakt(lambda v: _gebundene_entscheidung(pred, self.dec, self.dpub, self.opub, expected_maker=v,
                                                       now=T_IM_FENSTER)[0], MAKER, self)
        env = self._out()
        pruefe_exakt(lambda v: self._verify(env, decision_maker_id=v)["bound_decision_ok"] is True, MAKER, self)

    def test_a_bound_decision_needs_the_expected_decision_maker(self):
        r = self._verify(self._out(), decision_maker_id=None)
        self.assertIs(r["bound_decision_ok"], False)
        self.assertFalse(r["ok"])

    def test_a_malformed_t_does_not_bind(self):
        for now in (True, 1.5, "1783595820", -10 ** 20):
            with self.subTest(now=now):
                self.assertIs(self._verify(self._out(), now=now)["bound_decision_ok"], False)


class TestSection34Cli(_Paar):
    def setUp(self):
        super().setUp()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.decision = self.tmp / "decision.json"
        self.decision.write_text(json.dumps(self.dec), encoding="utf-8")
        self.effect = self.tmp / "effect.bin"
        self.effect.write_bytes(EFFECT)

    def _cli(self, env, *extra):
        rec = self.tmp / "outcome.json"
        rec.write_text(json.dumps(env), encoding="utf-8")
        return _run(["outcome", "verify", str(rec), "--pub", base64.b64encode(self.opub).decode(), "--strict",
                     *extra])

    def _alle(self):
        return ["--executor-id", EXECUTOR, "--effect", str(self.effect), "--decision", str(self.decision),
                "--decision-pub", base64.b64encode(self.dpub).decode(), "--decision-maker-id", MAKER,
                "--verification-time", T_TEXT]

    def test_cli_expired_decision_exit_2(self):
        # Without --verification-time the bound decision is judged at the wall clock, where it has expired.
        alle = self._alle()
        rc, out, _ = self._cli(self._out(), *alle[:-2])
        self.assertEqual(rc, 2)
        self.assertIn("BOUND_DECISION: FAIL", out)

    def test_cli_verification_time_in_the_future_exit_2(self):
        alle = self._alle()
        rc, _, _ = self._cli(self._out(), *alle[:-1], "2999-01-01T00:00:00Z")
        self.assertEqual(rc, 2)

    def test_cli_all_hold_exit_0(self):
        rc, out, err = self._cli(self._out(), *self._alle())
        self.assertEqual(rc, 0, err)
        for zeile in ("EXECUTOR_ID: OK", "EFFECT: OK", "BOUND_DECISION: OK"):
            self.assertIn(zeile, out)

    def test_cli_f6_other_executor_exit_2(self):
        rc, out, _ = self._cli(self._out(executor={"id": "forge:another-actor"}), *self._alle())
        self.assertEqual(rc, 2)
        self.assertIn("EXECUTOR_ID: MISMATCH", out)

    def test_cli_f7_effect_without_digest_exit_2(self):
        p = _outcome_predicate(self.dec)
        del p["effectDigest"]
        rc, out, _ = self._cli(emit_outcome_receipt(p, self.os_), *self._alle())
        self.assertEqual(rc, 2)
        self.assertIn("EFFECT: MISMATCH", out)

    def test_cli_f8_outside_the_window_exit_2(self):
        rc, out, _ = self._cli(self._out(performedAt="2026-07-09T11:21:00Z"), *self._alle())
        self.assertEqual(rc, 2)
        self.assertIn("BOUND_DECISION: FAIL", out)

    def test_cli_without_the_new_options_unchanged(self):
        rc, out, _ = self._cli(self._out())
        self.assertEqual(rc, 0)
        for prefix in ("EXECUTOR_ID:", "EFFECT:", "BOUND_DECISION:"):
            self.assertNotIn(prefix, out)

    def test_cli_decision_without_its_key_exit_2(self):
        rc, _, _ = self._cli(self._out(), "--decision", str(self.decision))
        self.assertEqual(rc, 2)

    def test_cli_empty_values_are_not_dropped(self):
        for option in ("--effect", "--decision", "--executor-id"):
            with self.subTest(option=option):
                extra = [option, ""] + (["--decision-pub", base64.b64encode(self.dpub).decode()]
                                        if option == "--decision" else [])
                rc, _, _ = self._cli(self._out(), *extra)
                self.assertEqual(rc, 2)

    def test_cli_json_reports_the_axes(self):
        rc, out, _ = self._cli(self._out(executor={"id": "forge:another-actor"}), *self._alle(), "--json")
        self.assertEqual(rc, 2)
        rep = json.loads(out)
        self.assertIs(rep["executor_id_ok"], False)
        self.assertIs(rep["effect_bytes_ok"], True)
        self.assertIn("bound_decision_ok", rep)


if __name__ == "__main__":
    unittest.main()
