"""Finding 14a (self-fixable parts) — ADR 0006 B3 OPEN items closed additively:

  (b) RFC3161/OTS<->ArchiveTimeStamp integration glue: an ATS may carry a DETACHED external_token_type /
      external_token / external_token_frozen, verified via `renewal._verify_ats_external_token` against the
      ALREADY-HARDENED standalone `anchors_rfc3161.verify_rfc3161` / `anchors_ots.verify_opentimestamps` —
      pure glue, no new cryptography.
  (c) Truncation-replay-of-an-older-prefix detection via `verify_sequence(..., known_newest_token_digest=…)`.

NOT built (honest, ADR 0006, unchanged): the full ASN.1/XMLERS export; a signature-algorithm staleness
trigger in RenewalPolicy; confirmed-OTS/real-TSA network calls (Owner-GO-gated, out of scope here).
"""
from __future__ import annotations

import dataclasses
import unittest

try:
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except ImportError:
    _HAS_OTS = False

from proofbundle.renewal import (
    ArchiveTimeStamp,
    anchor_proof_digest,
    build_initial_sequence,
    renew_timestamp,
    verify_sequence as _verify_sequence,
)

DATA = ["a" * 64, "b" * 64, "c" * 64]


def verify_sequence(seq, data, **kw):
    kw.setdefault("allow_unauthenticated_anchor", True)
    return _verify_sequence(seq, data, **kw)


def _initial(time: int = 1000):
    return build_initial_sequence(DATA, hash_alg="sha256", time=time)


def _check(result, name: str):
    for c in result.checks:
        if c.name == name:
            return c
    return None


class TestExternalTokenFieldDefaults(unittest.TestCase):
    def test_default_ats_has_no_external_token(self):
        seq = _initial()
        ats = seq[0][0]
        self.assertEqual(ats.external_token_type, "")
        self.assertEqual(ats.external_token, b"")
        self.assertEqual(ats.external_token_frozen, {})

    def test_external_token_not_in_token_string(self):
        # DETACHED evidence (mirrors anchors.py): attaching a huge external_token must not change token(),
        # so a later renewal's covering hash is unaffected by it.
        seq = _initial()
        base = seq[0][0]
        with_token = dataclasses.replace(base, external_token_type="rfc3161-tsa",
                                         external_token=b"\x00" * 4096,
                                         external_token_frozen={"rootCertsDerB64": ["x"]})
        self.assertEqual(base.token(), with_token.token())

    def test_no_external_token_check_surfaced_when_absent(self):
        seq = _initial()
        r = verify_sequence(seq, DATA)
        self.assertIsNone(_check(r, "renewal:external_token"))
        self.assertTrue(r.ok)


class TestVerifyAtsExternalTokenGlue(unittest.TestCase):
    """Direct unit tests of `_verify_ats_external_token` — no library needed for the fail-closed paths."""

    def test_absent_type_reports_absent(self):
        from proofbundle.renewal import _verify_ats_external_token
        ats = _initial()[0][0]
        res = _verify_ats_external_token(ats)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "absent")

    def test_unknown_type_reports_absent_not_crash(self):
        from proofbundle.renewal import _verify_ats_external_token
        ats = dataclasses.replace(_initial()[0][0], external_token_type="carrier-pigeon",
                                  external_token=b"x")
        res = _verify_ats_external_token(ats)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "absent")

    def test_malformed_covered_digest_fails_closed_not_raise(self):
        from proofbundle.renewal import _verify_ats_external_token
        ats = ArchiveTimeStamp("sha256", "not-hex!!", 1000, external_token_type="rfc3161-tsa",
                               external_token=b"x")
        res = _verify_ats_external_token(ats)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "malformed")

    def test_rfc3161_missing_extra_fails_closed_not_raise(self):
        # exercises the real dispatch path into anchors_rfc3161 (whether or not the extra is installed —
        # either way this must return a fail-closed dict, never raise).
        from proofbundle.renewal import _verify_ats_external_token
        ats = dataclasses.replace(_initial()[0][0], external_token_type="rfc3161-tsa",
                                  external_token=b"not-a-real-der-token")
        res = _verify_ats_external_token(ats)
        self.assertFalse(res["ok"])

    def test_opentimestamps_malformed_proof_fails_closed_not_raise(self):
        from proofbundle.renewal import _verify_ats_external_token
        ats = dataclasses.replace(_initial()[0][0], external_token_type="opentimestamps",
                                  external_token=b"not-a-real-ots-proof")
        res = _verify_ats_external_token(ats)
        self.assertFalse(res["ok"])

    def test_verifier_exception_is_caught_fail_closed(self):
        from proofbundle.renewal import _verify_ats_external_token
        import proofbundle.anchors_rfc3161 as anchors_rfc3161
        import unittest.mock as mock
        ats = dataclasses.replace(_initial()[0][0], external_token_type="rfc3161-tsa",
                                  external_token=b"x")
        with mock.patch.object(anchors_rfc3161, "verify_rfc3161", side_effect=RuntimeError("boom")):
            res = _verify_ats_external_token(ats)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "verifier_error")


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestExternalTokenOtsThroughVerifySequence(unittest.TestCase):
    """End-to-end: a REAL OTS proof attached to the newest ATS, verified through verify_sequence."""

    @staticmethod
    def _serialize(dtf) -> bytes:
        from opentimestamps.core.serialize import BytesSerializationContext
        ctx = BytesSerializationContext()
        dtf.serialize(ctx)
        return ctx.getbytes()

    def _pending_proof(self, covered_digest_hex: str) -> bytes:
        from opentimestamps.core.notary import PendingAttestation
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
        msg = bytes.fromhex(covered_digest_hex)
        ts = Timestamp(msg)
        ts.attestations.add(PendingAttestation("https://alice.btc.calendar.opentimestamps.org"))
        return self._serialize(DetachedTimestampFile(OpSHA256(), ts))

    def _upgraded_proof(self, covered_digest_hex: str, height=800000) -> bytes:
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
        msg = bytes.fromhex(covered_digest_hex)
        ts = Timestamp(msg)
        ts.attestations.add(BitcoinBlockHeaderAttestation(height))
        return self._serialize(DetachedTimestampFile(OpSHA256(), ts))

    def test_pending_ots_token_tolerated_by_default(self):
        seq = _initial()
        newest = seq[0][0]
        proof = self._pending_proof(newest.covered_digest)
        with_token = dataclasses.replace(newest, external_token_type="opentimestamps", external_token=proof)
        r = verify_sequence([[with_token]], DATA)
        ck = _check(r, "renewal:external_token")
        self.assertIsNotNone(ck)
        self.assertTrue(ck.ok)   # WARN (pending) tolerated by default
        self.assertTrue(r.ok, [str(c) for c in r.checks if not c.ok])

    def test_pending_ots_token_fails_closed_under_require_external_token(self):
        seq = _initial()
        newest = seq[0][0]
        proof = self._pending_proof(newest.covered_digest)
        with_token = dataclasses.replace(newest, external_token_type="opentimestamps", external_token=proof)
        r = verify_sequence([[with_token]], DATA, require_external_token=True)
        self.assertFalse(_check(r, "renewal:external_token").ok)
        self.assertFalse(r.ok)

    def test_confirmed_ots_token_verifies_with_rp_trust(self):
        seq = _initial()
        newest = seq[0][0]
        proof = self._upgraded_proof(newest.covered_digest, height=800000)
        msg = bytes.fromhex(newest.covered_digest)
        with_token = dataclasses.replace(newest, external_token_type="opentimestamps", external_token=proof)
        rp_trust = {"bitcoin_block_headers": {"800000": msg.hex()}}
        r = verify_sequence([[with_token]], DATA, rp_trust=rp_trust, require_external_token=True)
        self.assertTrue(_check(r, "renewal:external_token").ok, r.as_dict())
        self.assertTrue(r.ok, [str(c) for c in r.checks if not c.ok])

    def test_confirmed_without_rp_trust_needs_rp_trust_not_hard_fail(self):
        # WITHOUT require_external_token, needs_rp_trust is NOT a warn state (ok=False, warn=False in the
        # OTS verifier) — this must fail the check by default (only pending/warn is tolerated).
        seq = _initial()
        newest = seq[0][0]
        proof = self._upgraded_proof(newest.covered_digest, height=800000)
        with_token = dataclasses.replace(newest, external_token_type="opentimestamps", external_token=proof)
        r = verify_sequence([[with_token]], DATA)
        self.assertFalse(_check(r, "renewal:external_token").ok)
        self.assertFalse(r.ok)

    def test_wrong_root_ots_token_fails_closed(self):
        # the OTS proof commits to a DIFFERENT message than this ATS's covered_digest -> unbound -> FAIL.
        seq = _initial()
        newest = seq[0][0]
        proof = self._pending_proof(("f" * 64))   # unrelated covered_digest
        with_token = dataclasses.replace(newest, external_token_type="opentimestamps", external_token=proof)
        r = verify_sequence([[with_token]], DATA)
        self.assertFalse(_check(r, "renewal:external_token").ok)
        self.assertFalse(r.ok)


class TestNoRollbackDetection(unittest.TestCase):
    """Finding 14a-c: RFC 4998 does not itself defend against a stale-prefix truncation replay."""

    def test_no_check_surfaced_when_param_omitted(self):
        seq = renew_timestamp(_initial(), time=2000)
        r = verify_sequence(seq, DATA)
        self.assertIsNone(_check(r, "renewal:no_rollback"))

    def test_unchanged_newest_matches_known_digest(self):
        seq = _initial()
        known = anchor_proof_digest(seq[0][0])
        r = verify_sequence(seq, DATA, known_newest_token_digest=known)
        self.assertTrue(_check(r, "renewal:no_rollback").ok)
        self.assertTrue(r.ok)

    def test_forward_progress_after_known_digest_still_passes(self):
        # the RP last observed the INITIAL ats; the sequence has since legitimately grown (renewed) — the
        # known ATS is still present (just no longer the newest) -> PASS (forward progress, not a rollback).
        seq = _initial()
        known = anchor_proof_digest(seq[0][0])
        grown = renew_timestamp(seq, time=2000)
        r = verify_sequence(grown, DATA, known_newest_token_digest=known)
        self.assertTrue(_check(r, "renewal:no_rollback").ok)
        self.assertTrue(r.ok)

    def test_truncated_prefix_replay_is_detected(self):
        # THE attack: the RP last observed the RENEWED (2-ATS) sequence; an attacker replays only the
        # untruncated ORIGINAL (1-ATS) prefix, dropping the later renewal — the RP's remembered newest ATS
        # digest is nowhere in the truncated sequence -> FAIL (fail-closed).
        seq = _initial()
        grown = renew_timestamp(seq, time=2000)
        known = anchor_proof_digest(grown[0][1])          # the RP last saw the RENEWED newest ATS
        truncated = [[grown[0][0]]]                        # attacker replays only the original prefix
        r = verify_sequence(truncated, DATA, known_newest_token_digest=known)
        self.assertFalse(_check(r, "renewal:no_rollback").ok)
        self.assertFalse(r.ok)

    def test_unrelated_digest_not_found_fails_closed(self):
        seq = _initial()
        r = verify_sequence(seq, DATA, known_newest_token_digest="00" * 32)
        self.assertFalse(_check(r, "renewal:no_rollback").ok)
        self.assertFalse(r.ok)


if __name__ == "__main__":
    unittest.main()
