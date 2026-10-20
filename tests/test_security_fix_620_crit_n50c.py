"""Addendum 50c (`KRAXO-CLOUD-N50C-CROSSCHECK-DECISION-ZUM-RECORDEDAT-01`, Z309 / 6.2.0).

Holding test for a known open Rust item, in the `BLOCKED-rust-fix-open` pattern.

Since CX-02 (Addendum 49b) the Python decision verify folds an ``expiresAt`` that is past against the
wall clock into exit 2. The decision conformance fixtures carry a fixed-date ``validity.expiresAt``
(2026-07-09), so a bare ``decision verify`` of such a receipt exits 2 today, while the Rust verifier does
not evaluate ``validity.expiresAt`` at all and would return VERIFIED — the 15 crosscheck divergences this
Addendum addresses. ``tools/pb_verify_rs/crosscheck.py`` now evaluates the Python decision side AS OF the
receipt's own ``recordedAt`` (else ``decidedAt``), so the differential measures the lineage/policy verdict,
not the fixture clock. This file pins that behaviour at the Python layer:

1. A decision receipt whose ``validity.expiresAt`` is in the past verifies to exit 2 WITHOUT a
   ``--verification-time`` (the wall-clock freshness fold) and NOT to exit 2 WITH
   ``--verification-time`` = its ``recordedAt`` (the historical instant inside its validity window).
2. The matching Rust assertion — that the Rust verifier ALSO rejects an expired ``expiresAt`` — is a
   separate open Rust item (Rust freshness is post-tag), so it is recorded here with ``skipTest`` and
   flips to a hard assertion once the Rust verifier evaluates ``expiresAt``.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from proofbundle import generate_signer
from proofbundle.cli import main
from proofbundle.decision import emit_decision_receipt

_EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _raw_pub(signer) -> bytes:
    return signer.public_key().public_bytes_raw()


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue() + err.getvalue()


def _expired_decision_receipt():
    """A genuine decision receipt whose validity.expiresAt is past at the wall clock but AFTER its own
    recordedAt — the shape of the decision conformance fixtures (fixed-date 2026-07-09 window). decidedAt
    10:00:00Z, recordedAt 10:00:01Z, expiresAt 10:05:00Z: valid as of recordedAt, expired at today's wall
    clock. Re-signed, so it is a genuine receipt, not a tampered one."""
    predicate = json.loads((_EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))
    predicate.setdefault("validity", {})["expiresAt"] = "2026-07-09T10:05:00Z"
    predicate["decidedAt"] = "2026-07-09T10:00:00Z"
    predicate["recordedAt"] = "2026-07-09T10:00:01Z"
    signer = generate_signer()
    env = emit_decision_receipt(predicate, signer, strict=True)
    return env, signer, predicate


class ExpiredDecisionIsEvaluatedAsOfRecordedAt(unittest.TestCase):
    """VERTRAG 1/2 (Python side): the wall-clock expiry that produced the crosscheck divergence is real,
    and pinning the verification time to the receipt's recordedAt removes it."""

    def _verify(self, env, pub_b64, *, verification_time=None):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "receipt.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(env))
            argv = ["decision", "verify", path, "--pub", pub_b64, "--json"]
            if verification_time is not None:
                argv += ["--verification-time", verification_time]
            return _run(argv)

    def test_wall_clock_expiry_exits_2_and_recordedat_pin_does_not(self):
        env, signer, predicate = _expired_decision_receipt()
        pub_b64 = base64.b64encode(_raw_pub(signer)).decode("ascii")
        recorded_at = predicate.get("recordedAt") or predicate.get("decidedAt")

        rc_raw, _out_raw = self._verify(env, pub_b64)
        self.assertEqual(rc_raw, 2,
                         "a decision receipt whose validity.expiresAt is past exits 2 at the wall clock "
                         "(CX-02 freshness fold) — this is the source of the crosscheck divergence")

        rc_pinned, _out_pinned = self._verify(env, pub_b64, verification_time=recorded_at)
        self.assertNotEqual(rc_pinned, 2,
                            "pinning the verification time to the receipt's recordedAt removes the "
                            "wall-clock freshness fold, so the differential measures lineage/policy")


class RustExpiresAtIsAnOpenItem(unittest.TestCase):
    """VERTRAG 2/3: the Rust verifier does not evaluate validity.expiresAt, so a wall-clock-expired but
    otherwise valid decision receipt is VERIFIED by Rust while Python exits 2. The crosscheck papers over
    this by pinning the Python side to recordedAt; closing it needs Rust freshness, which is post-tag.
    This assertion is held open in the BLOCKED-rust-fix-open pattern and flips once Rust judges expiresAt.
    The gap is named only in the bundle report, never the public RESTRISIKO."""

    def test_rust_rejects_expired_expiresat(self):
        self.skipTest("BLOCKED-rust-fix-open: the Rust verifier does not evaluate validity.expiresAt "
                      "(no expiresAt handling under tools/pb_verify_rs/src); a wall-clock-expired but "
                      "otherwise valid decision receipt is VERIFIED by Rust while Python exits 2. Rust "
                      "freshness is a post-tag item; crosscheck.py pins the Python decision verify to "
                      "recordedAt (Addendum 50c) so the differential is not masked meanwhile. This flips "
                      "to a hard assertion once the Rust verifier evaluates expiresAt.")


if __name__ == "__main__":
    unittest.main()
