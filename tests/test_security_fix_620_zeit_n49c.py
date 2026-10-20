"""Addendum 49c (`KRAXO-CLOUD-N49C-VERIFICATION-TIME-NUR-Z-UND-DOKU-01`, Z309 / 6.2.0).

F-01 (K-C, P2): `decision verify --verification-time` and `verify-enclave --verification-time` share the helper
``cli._historical_now_posix``. Its docstring and the two `--verification-time` help strings name ISO-8601 with a
literal ``Z``, yet the helper called ``policy._parse_iso_utc`` directly, which silently reads a zone offset
(``+00:00`` included) or a naive timestamp as UTC. The promised input bound was not enforced. 49c narrows ONLY
this shared helper: a non-``Z`` form is a format error (ValueError), surfaced as exit 2 at both CLI surfaces.
``policy._parse_iso_utc`` and the older `verify --policy --verification-time` path stay unchanged (VERTRAG 2).

F-02 (K-C, P1): `docs/predicates/decision-receipt.md` said ``freshness_ok`` is "always null for decision
receipts". Since N49 a present ``validity.expiresAt`` IS judged (at ``--verification-time`` else the wall clock)
and a false folds into ``ok`` / exit 2. The doc is corrected; this file locks the three measured cases.

RED at the zeit head 8127b81a0e2b1734919d1f8d3e976901fb0ec961 (the helper accepts offset/naive, so the CLI
exits 0), GREEN at the 49c head. The future-``Z`` and F-02 cases are coverage locks (green at both heads).
Only fail-closed narrowing and the in-validity control are tested; no judge changes its verdict for a ``Z`` input.
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

from proofbundle.emit import generate_signer  # noqa: E402

_EXAMPLES = REPO / "examples"


def _raw(sk) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _cli_run(argv):
    """Run the CLI; return (rc, stdout, stderr). A subcommand returns the int; an argparse usage error raises
    SystemExit. stdout and stderr are captured separately (a receipt's bytes can reach either)."""
    from proofbundle.cli import main
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(list(argv))
    except SystemExit as exc:
        rc = int(exc.code) if exc.code is not None else 0
    else:
        rc = 0 if rc is None else int(rc)
    return rc, out.getvalue(), err.getvalue()


def _write(tmp, name, text) -> str:
    p = os.path.join(tmp, name)
    Path(p).write_text(text, encoding="utf-8")
    return p


# The non-Z forms of one and the same UTC instant, which _parse_iso_utc reads as that same instant.
_NON_Z = ("2026-01-01T00:00:00+01:00", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00")
_PAST_Z = "2026-01-01T00:00:00Z"
_FUTURE_Z = "2099-01-01T00:00:00Z"


class TheSharedHelperAcceptsOnlyAZInstant(unittest.TestCase):
    """VERTRAG 1/5 at the unit: `cli._historical_now_posix` rejects a zone offset (``+00:00`` included) and a
    naive time as a format error, accepts a past ``Z`` instant unchanged, and still rejects a future ``Z``."""

    def test_offset_and_naive_forms_are_a_format_error(self):
        from proofbundle.cli import _historical_now_posix
        for value in _NON_Z:
            with self.subTest(value=value), self.assertRaises(ValueError) as cm:
                _historical_now_posix(value)
            self.assertIn("'Z'", str(cm.exception),
                          "the format error must name the required Z form")

    def test_not_a_timestamp_is_a_format_error(self):
        from proofbundle.cli import _historical_now_posix
        with self.assertRaises(ValueError):
            _historical_now_posix("not-a-time")

    def test_a_past_Z_instant_is_accepted_unchanged(self):
        # Control (VERTRAG 6): a Z input behaves exactly as before — parsed to the one POSIX evaluation second.
        from proofbundle.cli import _historical_now_posix
        self.assertEqual(_historical_now_posix(_PAST_Z), 1767225600)

    def test_none_stays_none(self):
        from proofbundle.cli import _historical_now_posix
        self.assertIsNone(_historical_now_posix(None))

    def test_a_future_Z_instant_is_rejected_as_not_past(self):
        # Coverage lock (green at both heads): the past-only guard already held; it was untested for this helper.
        from proofbundle.cli import _historical_now_posix
        with self.assertRaises(ValueError) as cm:
            _historical_now_posix(_FUTURE_Z)
        self.assertIn("must be in the past", str(cm.exception))


class DecisionVerifyRequiresAZVerificationTime(unittest.TestCase):
    """VERTRAG 5, surface 1: `decision verify --verification-time` exits 2 with the Z-format message for an
    offset/naive value; a past ``Z`` control still exits 0. The receipt is valid (expiresAt 2099), so the ONLY
    variable is the time format. RED at 8127b81a (the offset is accepted → exit 0)."""

    def _receipt(self, tmp):
        from proofbundle.decision import emit_decision_receipt
        pred = json.loads((_EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        pred["validity"]["expiresAt"] = "2099-01-01T00:00:00Z"
        aud, nonce = pred["validity"]["audience"][0], pred["validity"]["nonce"]
        sk = generate_signer()
        env = emit_decision_receipt(pred, sk, strict=True)
        path = _write(tmp, "receipt.json", json.dumps(env))
        return path, _b64(_raw(sk)), aud, nonce

    def _argv(self, path, pub, aud, nonce, *extra):
        return ["decision", "verify", path, "--pub", pub, "--strict", "--aud", aud, "--nonce", nonce, *extra]

    def test_offset_and_naive_verification_times_exit_2_with_the_format_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, pub, aud, nonce = self._receipt(tmp)
            for value in _NON_Z:
                with self.subTest(value=value):
                    rc, _out, err = _cli_run(self._argv(path, pub, aud, nonce, "--verification-time", value))
                    self.assertEqual(rc, 2, f"a non-Z --verification-time is a usage error; got {rc}")
                    self.assertIn("ISO-8601 UTC 'Z'", err)

    def test_a_past_Z_verification_time_still_exits_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, pub, aud, nonce = self._receipt(tmp)
            rc, _out, _err = _cli_run(self._argv(path, pub, aud, nonce, "--verification-time", _PAST_Z))
            self.assertEqual(rc, 0)

    def test_a_future_Z_verification_time_exits_2_as_not_past(self):
        # Coverage lock: a future Z is rejected (not a historical query) at both heads.
        with tempfile.TemporaryDirectory() as tmp:
            path, pub, aud, nonce = self._receipt(tmp)
            rc, _out, err = _cli_run(self._argv(path, pub, aud, nonce, "--verification-time", _FUTURE_Z))
            self.assertEqual(rc, 2)
            self.assertIn("must be in the past", err)


class VerifyEnclaveRequiresAZVerificationTime(unittest.TestCase):
    """VERTRAG 5, surface 2: `verify-enclave --verification-time` exits 2 with the Z-format message for an
    offset/naive value; a past ``Z`` control within the window still exits 0. RED at 8127b81a (the offset is
    accepted and, being inside the EAT window, exits 0)."""

    _IAT = 1_600_000_000           # 2020-09-13T12:26:40Z
    _EXP = 1_600_000_000 + 86400   # one day later
    # Non-Z forms of an instant INSIDE the EAT window, so at the base head they are accepted and exit 0 — the
    # red-at-base signal is a clean 0 (accepted) vs 2 (format error at the 49c head).
    _NON_Z_IN_WINDOW = ("2020-09-14T00:00:00+01:00", "2020-09-14T00:00:00+00:00", "2020-09-14T00:00:00")
    _PAST_Z_IN_WINDOW = "2020-09-14T00:00:00Z"

    def _setup(self, tmp):
        from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
        from proofbundle.experimental.enclave import enclave_binding_for, issue_enclave_attestation
        signer = generate_signer()
        claim, _ = build_eval_claim(
            suite="safety", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
            score="0.9", n=100, model_id="m", dataset_id="d", issuer="placeholder",
            timestamp="2026-07-09T10:00:00Z", assurance_level="enclave_attested")
        bundle = emit_eval_receipt(claim, signer)
        binding = enclave_binding_for(bundle)
        verifier = generate_signer()
        eat = issue_enclave_attestation(binding, verifier, profile="p", tier="affirming",
                                        iat=self._IAT, exp=self._EXP)
        rcpt = _write(tmp, "bundle.json", json.dumps(bundle))
        eatp = _write(tmp, "eat.jws", eat)
        return rcpt, eatp, _b64(_raw(verifier))

    def _argv(self, rcpt, eatp, vkey, *extra):
        return ["verify-enclave", eatp, "--receipt", rcpt, "--verifier-key", vkey, "--profile", "p", *extra]

    def test_offset_and_naive_verification_times_exit_2_with_the_format_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            rcpt, eatp, vkey = self._setup(tmp)
            for value in self._NON_Z_IN_WINDOW:
                with self.subTest(value=value):
                    rc, _out, err = _cli_run(self._argv(rcpt, eatp, vkey, "--verification-time", value))
                    self.assertEqual(rc, 2, f"a non-Z --verification-time is a usage error; got {rc}")
                    self.assertIn("ISO-8601 UTC 'Z'", err)

    def test_a_past_Z_verification_time_within_the_window_still_exits_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            rcpt, eatp, vkey = self._setup(tmp)
            rc, _out, _err = _cli_run(self._argv(rcpt, eatp, vkey, "--verification-time", self._PAST_Z_IN_WINDOW))
            self.assertEqual(rc, 0)


class DecisionReceiptFreshnessDocCases(unittest.TestCase):
    """F-02 behaviour lock (green at both heads): the three measured cases the corrected §7 now describes —
    absent expiresAt is null/exit 0, a past expiresAt is false/exit 2, a future expiresAt is true/exit 0.
    No ``--verification-time`` is given, so the verifier reads its wall clock."""

    def _run_json(self, tmp, expires):
        from proofbundle.decision import emit_decision_receipt
        pred = json.loads((_EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        if expires is None:
            pred["validity"].pop("expiresAt", None)
        else:
            pred["validity"]["expiresAt"] = expires
        aud, nonce = pred["validity"]["audience"][0], pred["validity"]["nonce"]
        sk = generate_signer()
        env = emit_decision_receipt(pred, sk, strict=True)
        path = _write(tmp, "receipt.json", json.dumps(env))
        rc, out, _err = _cli_run(["decision", "verify", path, "--pub", _b64(_raw(sk)),
                                  "--strict", "--aud", aud, "--nonce", nonce, "--json"])
        return rc, json.loads(out)

    def test_absent_expiresAt_is_null_and_exit_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, report = self._run_json(tmp, None)
            self.assertIsNone(report["freshness_ok"])
            self.assertIs(report["ok"], True)
            self.assertEqual(rc, 0)

    def test_an_expired_expiresAt_is_false_and_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, report = self._run_json(tmp, "2020-01-01T00:00:00Z")
            self.assertIs(report["freshness_ok"], False)
            self.assertIs(report["ok"], False)
            self.assertEqual(rc, 2)

    def test_a_future_expiresAt_is_true_and_exit_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, report = self._run_json(tmp, "2099-01-01T00:00:00Z")
            self.assertIs(report["freshness_ok"], True)
            self.assertIs(report["ok"], True)
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
