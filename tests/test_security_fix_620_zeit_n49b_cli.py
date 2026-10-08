"""Nachtrag 49b (`KRAXO-CLOUD-N49B-ZEIT-AN-JEDEM-RAND-01`, Z309 / 6.2.0) — the CLI edges.

CX-02 decision verify CLI: the exit ladder never folded the freshness axis, so an expired decision receipt
      (validity.expiresAt in the past, freshness_ok False, ok False) exited 0. It now exits 2, and a
      --verification-time flag pins the evaluation instant (historical, fixed integer).
CX-05 verify-enclave CLI: it called verify_enclave_attestation WITHOUT a `now`, so the EAT freshness was
      never judged on the CLI path. A --verification-time flag now pins the enclave evaluation instant.

Red at the Codex base dbe2dc18 (the exit fold absent; the --verification-time flags absent), green after.
Only fail-closed behaviour and the in-validity controls are tested, each with a FIXED evaluation time.
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


def _cli_exit(argv) -> int:
    """Run the CLI and return its exit code. main() returns the int for a subcommand; argparse usage errors
    raise SystemExit. stdout/stderr are swallowed (a receipt's bytes can reach them)."""
    from proofbundle.cli import main
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = main(list(argv))
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 0
    return 0 if rc is None else int(rc)


def _write(tmp, name, text) -> str:
    p = os.path.join(tmp, name)
    Path(p).write_text(text, encoding="utf-8")
    return p


class Cx02DecisionVerifyCliFoldsFreshness(unittest.TestCase):
    """An expired declared validity.expiresAt makes `decision verify` exit non-zero (2), never a silent 0."""

    def _receipt(self, tmp, expires):
        from proofbundle.decision import emit_decision_receipt
        pred = json.loads((_EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        pred["validity"]["expiresAt"] = expires
        aud, nonce = pred["validity"]["audience"][0], pred["validity"]["nonce"]
        sk = generate_signer()
        env = emit_decision_receipt(pred, sk, strict=True)
        path = _write(tmp, "receipt.json", json.dumps(env))
        return path, _b64(_raw(sk)), aud, nonce

    def test_an_expired_receipt_exits_non_zero(self):
        # No --verification-time: a decision verify reads the wall clock; an expiresAt in 2020 is long past.
        with tempfile.TemporaryDirectory() as tmp:
            path, pub, aud, nonce = self._receipt(tmp, "2020-01-01T00:00:00Z")
            rc = _cli_exit(["decision", "verify", path, "--pub", pub, "--strict", "--aud", aud, "--nonce", nonce])
            self.assertEqual(rc, 2)

    def test_control_within_validity_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, pub, aud, nonce = self._receipt(tmp, "2099-01-01T00:00:00Z")
            rc = _cli_exit(["decision", "verify", path, "--pub", pub, "--strict", "--aud", aud, "--nonce", nonce])
            self.assertEqual(rc, 0)

    def test_verification_time_pins_the_expiry_instant(self):
        # expiresAt 2026-05-01: AS OF 2026-09-01 it is expired (exit 2); AS OF 2026-01-01 it is still valid (0).
        with tempfile.TemporaryDirectory() as tmp:
            path, pub, aud, nonce = self._receipt(tmp, "2026-05-01T00:00:00Z")
            base = ["decision", "verify", path, "--pub", pub, "--strict", "--aud", aud, "--nonce", nonce]
            self.assertEqual(_cli_exit(base + ["--verification-time", "2026-09-01T00:00:00Z"]), 2)
            self.assertEqual(_cli_exit(base + ["--verification-time", "2026-01-01T00:00:00Z"]), 0)


class Cx05VerifyEnclaveCliPinsTheEvaluationTime(unittest.TestCase):
    """`verify-enclave --verification-time` judges the EAT freshness: AS OF after expiry it fails (exit 1),
    within the window it passes (0); without the flag the freshness is not judged (0, the N49 behaviour)."""

    _IAT = 1_600_000_000           # 2020-09-13T12:26:40Z
    _EXP = 1_600_000_000 + 86400   # one day later

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

    def test_an_expired_attestation_exits_non_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            rcpt, eatp, vkey = self._setup(tmp)
            rc = _cli_exit(self._argv(rcpt, eatp, vkey, "--verification-time", "2020-09-20T00:00:00Z"))
            self.assertEqual(rc, 1)

    def test_control_within_the_window_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            rcpt, eatp, vkey = self._setup(tmp)
            rc = _cli_exit(self._argv(rcpt, eatp, vkey, "--verification-time", "2020-09-14T00:00:00Z"))
            self.assertEqual(rc, 0)

    def test_control_without_verification_time_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            rcpt, eatp, vkey = self._setup(tmp)
            rc = _cli_exit(self._argv(rcpt, eatp, vkey))
            self.assertEqual(rc, 0)   # N49 behaviour: no evaluation time -> freshness not judged -> PASS


if __name__ == "__main__":
    unittest.main()
