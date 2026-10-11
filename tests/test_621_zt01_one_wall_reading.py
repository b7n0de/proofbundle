"""6.2.1 ZT-01: one wall-clock reading per policy-lifecycle evaluation (``policy._gemeinsame_fehler``).

The siblings of the class: ``evaluate_policy`` (the eval path), ``evaluate_decision_policy``, the derived
``deploymentReady`` of ``instantiate_template``, and the present-tense lifecycle of the ``verify`` and
``decision verify`` CLI. Each judged ``valid_from`` and ``valid_until`` at a wall-clock reading of its own, so two
readings could straddle ``valid_until``. Each now judges both at one instant.

Red at v6.2.0.
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
import warnings
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)


from proofbundle import emit_bundle, generate_signer, verify_bundle  # noqa: E402
from proofbundle import policy as _policy  # noqa: E402

with warnings.catch_warnings():
    warnings.simplefilter("ignore")


class _WallClock:
    """``policy.datetime`` with a ``now()`` that returns the given readings in turn and counts them."""

    def __init__(self, *readings):
        self.readings, self.count = list(readings), 0
        owner = self

        class _DT(datetime):
            @classmethod
            def now(cls, tz=None):
                value = owner.readings[min(owner.count, len(owner.readings) - 1)]
                owner.count += 1
                return value
        self.cls = _DT


_D2026 = datetime(2026, 1, 1, tzinfo=timezone.utc)
_D2028 = datetime(2028, 1, 1, tzinfo=timezone.utc)


class ZT01OneWallReading(unittest.TestCase):
    _POL = {"valid_from": "2025-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z"}

    def test_one_lifecycle_evaluation_reads_the_wall_clock_once(self):
        clock = _WallClock(_D2026, _D2028)
        with mock.patch.object(_policy, "datetime", clock.cls):
            _policy._gemeinsame_fehler(self._POL, None, now=None)
        self.assertLessEqual(clock.count, 1, "valid_from and valid_until judged at two different instants")

    def test_control_an_explicit_instant_reads_no_wall_clock(self):
        clock = _WallClock(_D2028)
        with mock.patch.object(_policy, "datetime", clock.cls):
            errors = _policy._gemeinsame_fehler(self._POL, None, now=_D2026)
        self.assertEqual((errors, clock.count), ([], 0))


def _pub_b64(sk) -> str:
    return base64.b64encode(sk.public_key().public_bytes_raw()).decode("ascii")


def _window(extra: dict) -> dict:
    return {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "zt-01",
            "valid_from": "2025-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z", **extra}


def _cli(argv) -> tuple[int, str]:
    from proofbundle.cli import main  # noqa: PLC0415
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = main(list(argv))
    return rc, out.getvalue()


class ZT01SiblingsReadOnce(unittest.TestCase):
    """Every sibling judges valid_from and valid_until at one instant: the policy helpers read the wall clock at
    most once (with the readings 2026 and then 2028, two readings would judge valid_until at 2028)."""

    def test_evaluate_policy_reads_the_wall_clock_once(self):
        sk = generate_signer()
        bundle = emit_bundle(b"zt-01", sk)
        result = verify_bundle(bundle)
        clock = _WallClock(_D2026, _D2028)
        with mock.patch.object(_policy, "datetime", clock.cls):
            out = _policy.evaluate_policy(bundle, result, _window({"allowed_issuers": [{"public_key_b64": _pub_b64(sk)}]}), now=None)
        self.assertLessEqual(clock.count, 1, out)
        lifecycle = {c["name"]: c["ok"] for c in out["checks"] if c["name"] in ("policy:not_expired",
                                                                                 "policy:not_before")}
        self.assertEqual(lifecycle, {"policy:not_expired": True, "policy:not_before": True}, out)

    def test_evaluate_decision_policy_reads_the_wall_clock_once(self):
        import test_decision_policy as TDP  # noqa: PLC0415
        from _decision_result_binding import bound_decision_result  # noqa: PLC0415
        from proofbundle.decision import build_decision_statement  # noqa: PLC0415
        _sk, pub = TDP._keys()
        stmt = build_decision_statement(TDP._pred("deny"))
        pol = _policy.load_policy({**TDP._policy_trusting(pub), "valid_from": "2025-01-01T00:00:00Z",
                                   "valid_until": "2027-01-01T00:00:00Z"})
        clock = _WallClock(_D2026, _D2028)
        with mock.patch.object(_policy, "datetime", clock.cls):
            r = _policy.evaluate_decision_policy(stmt, bound_decision_result(stmt, pub), pol,
                                                 signer_public_key_b64=pub, now=None)
        self.assertLessEqual(clock.count, 1, r)
        self.assertIs(r["policy_ok"], True, r)

    def test_instantiate_template_reads_the_wall_clock_at_most_once_in_the_policy_helpers(self):
        from proofbundle.policy_profiles import instantiate_template  # noqa: PLC0415
        clock = _WallClock(_D2026, _D2028)
        with mock.patch.object(_policy, "datetime", clock.cls):
            instantiate_template("strict-eval-template-v1", issuer_keys=[_pub_b64(generate_signer())],
                                 policy_id="zt-01", valid_until="2099-01-01T00:00:00Z",
                                 overlay={"valid_from": "2020-01-01T00:00:00Z"})
        self.assertLessEqual(clock.count, 1)

    def test_verify_cli_hands_one_instant_to_every_lifecycle_judgement(self):
        sk = generate_signer()
        with tempfile.TemporaryDirectory() as tmp:
            bp, pp = os.path.join(tmp, "b.json"), os.path.join(tmp, "p.json")
            Path(bp).write_text(json.dumps(emit_bundle(b"zt-01", sk)), encoding="utf-8")
            Path(pp).write_text(json.dumps(_window({"allowed_issuers": [{"public_key_b64": _pub_b64(sk)}],
                                                    "valid_until": "2099-01-01T00:00:00Z",
                                                    "valid_from": "2020-01-01T00:00:00Z"})), encoding="utf-8")
            clock = _WallClock(_D2026, _D2028)
            with mock.patch.object(_policy, "datetime", clock.cls):
                rc, out = _cli(["verify", "--json", bp, "--policy", pp])
        self.assertEqual(rc, 0, out)
        self.assertLessEqual(clock.count, 1, out)

    def test_decision_verify_cli_reads_the_present_once_for_both_statuses(self):
        import test_security_fix_620_zeit_r6b6 as R6B6  # noqa: PLC0415
        env, pub, aud, nonce, _sk = R6B6._signed_receipt()
        pol = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "zt-01",
               "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": pub}]},
               "valid_from": "2020-01-01T00:00:00Z", "valid_until": "2099-01-01T00:00:00Z"}
        with tempfile.TemporaryDirectory() as tmp:
            rp, pp = R6B6._write(tmp, "r.json", env), R6B6._write(tmp, "p.json", pol)
            clock = _WallClock(_D2026, _D2028)
            with mock.patch.object(_policy, "datetime", clock.cls):
                rc, out = _cli(["decision", "verify", rp, "--pub", pub, "--strict", "--aud", aud, "--nonce", nonce,
                                "--policy", pp, "--verification-time", "2024-01-01T00:00:00Z", "--json"])
        self.assertEqual(rc, 0, out)
        self.assertEqual(json.loads(out)["verification_time"]["current_policy_status"], "VALID")
        self.assertLessEqual(clock.count, 1, out)


if __name__ == "__main__":
    unittest.main()
