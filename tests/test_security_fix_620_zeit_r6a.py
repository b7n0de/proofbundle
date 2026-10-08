"""Addendum R6a-4 / R6a-5 / R6a-6 / R6a-7 (`KRAXO-CLOUD-R6A-SIEBEN-P1-VOR-CRIT-JSON-01`, Z309 / 6.2.0).

Reviewer round 6a, four P1 time-semantics findings on the decision verify path, reproduced by Cowork from the
delivered probes (probe_r6a_4..7). All measured at the zeit base 8127b81a and still open on the zeit head
d7cd59ce (N49c narrowed only the `Z` format of `--verification-time`, not these):

R6a-4 — a HISTORICAL `--verification-time` (or a historical `now`) relaxed the PRESENT-tense `safeForAutomation`
        verdict and was not labelled. SPEC 403-410: historical mode relaxes ONLY the POLICY verdict (exit code);
        `safeForAutomation` lifecycle inputs are evaluated at the REAL current time, so a policy expired OR
        not-yet-valid TODAY keeps safeForAutomation False; and the output is labelled VERIFICATION_TIME:
        HISTORICAL / CURRENT_POLICY_STATUS / HISTORICAL_POLICY_STATUS. The fix adds the present-tense lifecycle
        gate (library) and the labels (CLI), mirroring the eval verify path.
R6a-5 — an explicit `now` that is not an exact POSIX-seconds int, or is out of datetime's range (year 10000),
        silently fell back to the wall clock — only caught when validity.expiresAt was present. The fix validates
        the explicit `now` once at the edge and fails the verdict closed REGARDLESS of expiresAt, with no
        wall-clock fallback.
R6a-6 — with `now` omitted the receipt freshness and the policy lifecycle each read the wall clock separately;
        two readings can straddle a validity boundary. The fix reads the wall clock EXACTLY ONCE at the edge and
        threads that one instant through both.
R6a-7 — `--verification-time` with a sub-second fraction was truncated to the whole second before the expiry
        comparison, so e.g. `…00.750000Z` read as `…00` and passed an expiry at `…00.500000Z`. The fix rejects a
        fractional `--verification-time` fail-closed (never silently truncated).

RED at the zeit head d7cd59ce, GREEN after. Only fail-closed behaviour and its controls are tested, with test
keys only; the R6a-6 case replaces the receipt-side wall clock with one fixed reading to make the single-reading
property deterministic.
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
from types import SimpleNamespace
from unittest import mock

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle import decision as _decision  # noqa: E402
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt  # noqa: E402
from proofbundle.emit import generate_signer  # noqa: E402

_EXAMPLES = REPO / "examples"
_Y2020 = 1577836800        # 2020-01-01T00:00:00Z
_Y2022 = 1640995200        # 2022-01-01T00:00:00Z


def _raw(sk) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _signed_receipt(*, with_expires: str | None = None):
    """A strict decision receipt from the deny example; returns (env, pub_b64, aud, nonce). ``with_expires``
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
    return {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "r6a-zeit",
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


class R6a4HistoricalModeIsPresentTenseAndLabelled(unittest.TestCase):
    """SPEC 403-410: a historical evaluation time relaxes the POLICY verdict/exit only; safeForAutomation stays
    a present-tense verdict, and the output is labelled."""

    def test_library_expired_today_policy_keeps_safeforautomation_false(self):
        env, pub, aud, nonce, _sk = _signed_receipt()
        # Policy expired TODAY (valid_until 2021) but valid AS OF the historical now (2020).
        r = verify_decision_receipt(env, base64.b64decode(pub), strict=True, expected_audience=aud,
                                    expected_nonce=nonce, policy=_policy(pub, "2021-01-01T00:00:00Z"), now=_Y2020)
        self.assertIs(r["policy_ok"], True, "the POLICY verdict passes AS OF the historical instant")
        self.assertIs(r["automation"]["safeForAutomation"], False,
                      "a policy expired TODAY is never automation-safe, even under a historical now")
        self.assertIn("POLICY_EXPIRED", r["automation"]["automationBlockers"])

    def test_library_control_valid_today_policy_stays_safe_under_a_historical_now(self):
        env, pub, aud, nonce, _sk = _signed_receipt()
        r = verify_decision_receipt(env, base64.b64decode(pub), strict=True, expected_audience=aud,
                                    expected_nonce=nonce, policy=_policy(pub, "2099-01-01T00:00:00Z"), now=_Y2020)
        self.assertIs(r["policy_ok"], True)
        self.assertIs(r["automation"]["safeForAutomation"], True)

    def test_cli_historical_expired_policy_exits_zero_but_is_unsafe_and_labelled(self):
        with tempfile.TemporaryDirectory() as tmp:
            env, pub, aud, nonce, _sk = _signed_receipt()
            rp = _write(tmp, "r.json", env)
            pol = _write(tmp, "p.json", _policy(pub, "2021-01-01T00:00:00Z"))
            rc, out = _cli_run(["decision", "verify", rp, "--pub", pub, "--strict", "--aud", aud,
                                "--nonce", nonce, "--policy", pol, "--json",
                                "--verification-time", "2020-01-01T00:00:00Z"])
            self.assertEqual(rc, 0, out)   # POLICY passes historically -> exit 0
            rep = json.loads(out)
            self.assertIs(rep["policy_ok"], True)
            self.assertIs(rep["automation"]["safeForAutomation"], False)
            self.assertIn("POLICY_EXPIRED", rep["automation"]["automationBlockers"])
            self.assertEqual(rep["verification_time"]["mode"], "HISTORICAL")
            self.assertEqual(rep["verification_time"]["current_policy_status"], "EXPIRED")
            self.assertEqual(rep["verification_time"]["historical_policy_status"], "PASS")

    def test_cli_present_mode_carries_no_historical_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            env, pub, aud, nonce, _sk = _signed_receipt()
            rp = _write(tmp, "r.json", env)
            pol = _write(tmp, "p.json", _policy(pub, "2099-01-01T00:00:00Z"))
            rc, out = _cli_run(["decision", "verify", rp, "--pub", pub, "--strict", "--aud", aud,
                                "--nonce", nonce, "--policy", pol, "--json"])
            self.assertEqual(rc, 0, out)
            self.assertNotIn("verification_time", json.loads(out))


class R6a5InvalidExplicitNowFailsClosed(unittest.TestCase):
    """An explicit `now` that is not an exact POSIX-seconds int in range fails the verdict closed, with no
    wall-clock fallback — whether or not the receipt declares an expiresAt."""

    def test_invalid_now_is_refused_without_expiresat(self):
        env, pub, aud, nonce, _sk = _signed_receipt()   # no expiresAt
        pol = _policy(pub, "2099-01-01T00:00:00Z")
        for label, now in (("text", "bad"), ("bool", True), ("year-10000", 253402300800)):
            with self.subTest(now=label):
                r = verify_decision_receipt(env, base64.b64decode(pub), strict=True, expected_audience=aud,
                                            expected_nonce=nonce, policy=pol, now=now)
                self.assertIs(r["ok"], False, f"a malformed now ({label}) must fail the verdict closed")
                self.assertIs(r["automation"]["safeForAutomation"], False)
                self.assertTrue(any("evaluation time" in e for e in r["errors"]), r["errors"])

    def test_control_valid_now_and_omitted_now_pass(self):
        env, pub, aud, nonce, _sk = _signed_receipt()
        pol = _policy(pub, "2099-01-01T00:00:00Z")
        for label, now in (("valid int", _Y2020), ("omitted", None)):
            with self.subTest(now=label):
                r = verify_decision_receipt(env, base64.b64decode(pub), strict=True, expected_audience=aud,
                                            expected_nonce=nonce, policy=pol, now=now)
                self.assertIs(r["ok"], True)


class R6a6OmittedNowIsOneClockReading(unittest.TestCase):
    """With `now` omitted the policy lifecycle is judged at the SAME single instant as the receipt edge, not a
    second independent wall-clock read (so two readings can never straddle a validity boundary)."""

    def test_policy_lifecycle_uses_the_single_edge_reading(self):
        env, pub, aud, nonce, _sk = _signed_receipt()   # no expiresAt
        # Policy valid_from 2020, valid_until 2099. The single edge reading is pinned to 2019 (before
        # valid_from). With one reading the policy is NOT YET VALID (judged at 2019); a second, real wall-clock
        # read (2026) would wrongly judge it valid.
        pol = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "r6a-zeit-6",
               "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": pub}]},
               "valid_from": "2020-01-01T00:00:00Z", "valid_until": "2099-01-01T00:00:00Z"}
        with mock.patch.object(_decision, "time", SimpleNamespace(time=lambda: float(_Y2020 - 86400))):
            r = verify_decision_receipt(env, base64.b64decode(pub), strict=True, expected_audience=aud,
                                        expected_nonce=nonce, policy=pol, now=None)
        self.assertIs(r["policy_ok"], False,
                      "the policy lifecycle is judged at the one edge reading (2019), not a fresh wall clock")
        self.assertIs(r["ok"], False)
        self.assertTrue(any("not yet valid" in e for e in r["errors"]), r["errors"])

    def test_control_edge_reading_inside_the_window_passes(self):
        env, pub, aud, nonce, _sk = _signed_receipt()
        pol = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "r6a-zeit-6",
               "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": pub}]},
               "valid_from": "2020-01-01T00:00:00Z", "valid_until": "2099-01-01T00:00:00Z"}
        with mock.patch.object(_decision, "time", SimpleNamespace(time=lambda: float(_Y2022))):
            r = verify_decision_receipt(env, base64.b64decode(pub), strict=True, expected_audience=aud,
                                        expected_nonce=nonce, policy=pol, now=None)
        self.assertIs(r["policy_ok"], True)
        self.assertIs(r["ok"], True)


class R6a7FractionalVerificationTimeNotTruncated(unittest.TestCase):
    """A `--verification-time` with a sub-second fraction is rejected (never truncated to the whole second,
    which passed an expiry that falls within that second)."""

    def _args(self, tmp, vt):
        env, pub, aud, nonce, _sk = _signed_receipt(with_expires="2026-01-01T00:00:00.500000Z")
        rp = _write(tmp, "r.json", env)
        return ["decision", "verify", rp, "--pub", pub, "--strict", "--aud", aud, "--nonce", nonce,
                "--verification-time", vt]

    def test_fractional_after_expiry_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = _cli_run(self._args(tmp, "2026-01-01T00:00:00.750000Z"))
            self.assertEqual(rc, 2, out)   # rejected as a format error, not silently truncated-and-passed

    def test_control_whole_second_before_expiry_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            for vt in ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000Z"):
                with self.subTest(verification_time=vt):
                    rc, out = _cli_run(self._args(tmp, vt))
                    self.assertEqual(rc, 0, out)   # a whole second before .5 is still fresh

    def test_control_next_whole_second_is_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = _cli_run(self._args(tmp, "2026-01-01T00:00:01Z"))
            self.assertEqual(rc, 2, out)   # a whole second after the expiry is expired (freshness fold)


if __name__ == "__main__":
    unittest.main()
