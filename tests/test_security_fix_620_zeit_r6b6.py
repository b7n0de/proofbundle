"""Addendum R6b-6 (`KRAXO-CLOUD-621-KERN-R6B-UND-ZT-01`, Z309 / 6.2.0) — the remaining neighbour path of R6a-4.

Reviewer round 6b, finding R6b-6 (= the owner's F4 group 3), reproduced by Cowork from the review and measured
at the zeit head 8e4bea0b (the R6a-4..7 head). SPEC 403-410: historical mode (`--verification-time` / an explicit
`now`) relaxes ONLY the POLICY verdict and exit code; `safeForAutomation` is a PRESENT-tense verdict whose
lifecycle AND freshness inputs are evaluated at the REAL current time. R6a-4 closed the POLICY-lifecycle half of
that; R6b-6 is the receipt-freshness half that was still open.

The defect at 8e4bea0b: the present-tense automation gate checks the policy lifecycle TODAY but not the receipt's
own validity.expiresAt. A receipt expired TODAY, verified at a historical instant where it WAS still fresh, under
a policy valid today, therefore kept `safeForAutomation=True` with empty blockers. The honest historical reading
(`freshness_ok=True`, exit 0, POLICY: PASS) is CORRECT and stays; only the present automation release was wrong.

Two probes, both RED at 8e4bea0b and GREEN after:
  * probe 1 (library) — Cowork's own construction: expiresAt 2022, historical now 2020, policy valid until 2099.
  * probe 2 (CLI) — the reviewer's exact reproduction: expiresAt 2021-01-01Z, policy until 2099-01-01Z,
    `--verification-time 2020-01-01T00:00:00Z`.
Controls prove the fix only narrows: a receipt still fresh TODAY stays safe under a historical now; an absent
expiresAt is not-applicable; and present mode is unchanged (an expired receipt still exits 2, safe False).
Only fail-closed behaviour and its controls are tested, with test keys only.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle.decision import emit_decision_receipt, verify_decision_receipt  # noqa: E402
from proofbundle.emit import generate_signer  # noqa: E402

_EXAMPLES = REPO / "examples"
_Y2020 = 1577836800        # 2020-01-01T00:00:00Z


def _raw(sk) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _signed_receipt(*, with_expires: str | None = None):
    """A strict decision receipt from the deny example; returns (env, pub_b64, aud, nonce, sk). ``with_expires``
    sets validity.expiresAt (default: the key is removed, so freshness is not-applicable)."""
    pred = json.loads((_EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))
    if with_expires is None:
        pred["validity"].pop("expiresAt", None)
    else:
        pred["validity"]["expiresAt"] = with_expires
    aud, nonce = pred["validity"]["audience"][0], pred["validity"]["nonce"]
    sk = generate_signer()
    return emit_decision_receipt(pred, sk, strict=True), _b64(_raw(sk)), aud, nonce, sk


def _policy(pub_b64: str, valid_until: str):
    return {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "r6b6-zeit",
            "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": pub_b64}]},
            "valid_until": valid_until}


def _cli_run(argv):
    """Run the CLI; return (exit_code, stdout_text)."""
    from proofbundle.cli import main
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = main(list(argv))
        code = 0 if rc is None else int(rc)
    except SystemExit as exc:
        code = int(exc.code) if exc.code is not None else 0
    return code, out.getvalue()


def _write(tmp, name, obj) -> str:
    p = os.path.join(tmp, name)
    Path(p).write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")
    return p


class R6b6PresentFreshnessIsRequiredForAutomation(unittest.TestCase):
    """SPEC 403-410: safeForAutomation is a present-tense verdict; a receipt expired TODAY is never
    automation-safe, even when a historical evaluation time made the POLICY verdict and the historical
    freshness check pass."""

    def test_probe1_library_expired_today_receipt_keeps_safeforautomation_false(self):
        # Cowork's own probe: expiresAt 2022 (past TODAY, future AS OF the historical now 2020), policy valid
        # today (until 2099). The historical freshness reading is True (the receipt WAS fresh in 2020) and the
        # policy passes historically -> at 8e4bea0b safeForAutomation came out True. It must be False.
        env, pub, aud, nonce, _sk = _signed_receipt(with_expires="2022-01-01T00:00:00Z")
        r = verify_decision_receipt(env, base64.b64decode(pub), strict=True, expected_audience=aud,
                                    expected_nonce=nonce, policy=_policy(pub, "2099-01-01T00:00:00Z"), now=_Y2020)
        self.assertIs(r["freshness_ok"], True, "the historical freshness reading stays honestly True")
        self.assertIs(r["policy_ok"], True, "the POLICY verdict passes AS OF the historical instant")
        self.assertIs(r["automation"]["safeForAutomation"], False,
                      "a receipt expired TODAY is never automation-safe, even under a historical now")
        self.assertIn("RECEIPT_EXPIRED", r["automation"]["automationBlockers"])

    def test_probe2_cli_reviewer_reproduction_expired_receipt_is_unsafe(self):
        # The reviewer's exact reproduction.
        with tempfile.TemporaryDirectory() as tmp:
            env, pub, aud, nonce, _sk = _signed_receipt(with_expires="2021-01-01T00:00:00Z")
            rp = _write(tmp, "r.json", env)
            pol = _write(tmp, "p.json", _policy(pub, "2099-01-01T00:00:00Z"))
            rc, out = _cli_run(["decision", "verify", rp, "--pub", pub, "--strict", "--aud", aud,
                                "--nonce", nonce, "--policy", pol, "--json",
                                "--verification-time", "2020-01-01T00:00:00Z"])
            self.assertEqual(rc, 0, out)   # POLICY passes historically -> exit 0 (unchanged, honest)
            rep = json.loads(out)
            self.assertIs(rep["freshness_ok"], True)      # the historical freshness reading stays True
            self.assertIs(rep["policy_ok"], True)
            self.assertEqual(rep["verification_time"]["mode"], "HISTORICAL")
            self.assertIs(rep["automation"]["safeForAutomation"], False,
                          "a receipt expired TODAY must not earn a present automation release")
            self.assertIn("RECEIPT_EXPIRED", rep["automation"]["automationBlockers"])

    def test_control_future_expiry_receipt_stays_safe_under_a_historical_now(self):
        # A receipt whose expiresAt is in the FUTURE relative to the real present time is still fresh TODAY:
        # the new gate must NOT over-block it. Verified at a historical now, under a policy valid today.
        env, pub, aud, nonce, _sk = _signed_receipt(with_expires="2099-01-01T00:00:00Z")
        r = verify_decision_receipt(env, base64.b64decode(pub), strict=True, expected_audience=aud,
                                    expected_nonce=nonce, policy=_policy(pub, "2099-01-01T00:00:00Z"), now=_Y2020)
        self.assertIs(r["freshness_ok"], True)
        self.assertIs(r["policy_ok"], True)
        self.assertIs(r["automation"]["safeForAutomation"], True)
        self.assertNotIn("RECEIPT_EXPIRED", r["automation"]["automationBlockers"])

    def test_control_absent_expiresat_is_not_applicable(self):
        # No validity.expiresAt: freshness is not-applicable (None) and the new present-tense gate never blocks.
        env, pub, aud, nonce, _sk = _signed_receipt()
        r = verify_decision_receipt(env, base64.b64decode(pub), strict=True, expected_audience=aud,
                                    expected_nonce=nonce, policy=_policy(pub, "2099-01-01T00:00:00Z"), now=_Y2020)
        self.assertIsNone(r["freshness_ok"])
        self.assertIs(r["automation"]["safeForAutomation"], True)
        self.assertNotIn("RECEIPT_EXPIRED", r["automation"]["automationBlockers"])

    def test_control_present_mode_expired_receipt_is_unchanged(self):
        # Present mode (no --verification-time): an expired receipt already exits 2 and is unsafe. The fix must
        # not change this honest present-mode behaviour.
        with tempfile.TemporaryDirectory() as tmp:
            env, pub, aud, nonce, _sk = _signed_receipt(with_expires="2021-01-01T00:00:00Z")
            rp = _write(tmp, "r.json", env)
            pol = _write(tmp, "p.json", _policy(pub, "2099-01-01T00:00:00Z"))
            rc, out = _cli_run(["decision", "verify", rp, "--pub", pub, "--strict", "--aud", aud,
                                "--nonce", nonce, "--policy", pol, "--json"])
            self.assertEqual(rc, 2, out)   # expired at present -> freshness fold, exit 2
            rep = json.loads(out)
            self.assertIs(rep["freshness_ok"], False)
            self.assertIs(rep["automation"]["safeForAutomation"], False)
            self.assertNotIn("verification_time", rep)   # no historical label in present mode


if __name__ == "__main__":
    unittest.main()
