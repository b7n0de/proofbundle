"""3.2.1 anchor-longevity hardening — the final-audit findings, each pinned RED->GREEN.

Covers the defense-in-depth gaps a six-lens + red-team audit surfaced in the 3.2.0 anchor modules
(all were non-default / incomplete-caller / weak-input cases, no forgery against a correct caller):

* F1 ``require_pq`` was a LABEL check ("mldsa" in sig_alg) — it now requires the PQ signature to be
  actually VERIFIED (only possible in authority_keys mode); a PQ label with an unverified anchor is not
  proof and fails closed.
* F2 ``evaluate_renewal_policy`` never flagged a FUTURE-dated newest ATS (age went negative -> perpetually
  "fresh"); a future time is now anomalous and overdue.
* R1 ``verify_sequence`` tolerated a deprecated newest hash with ``ok=True`` and no signal; it now surfaces
  a ``renewal:current_hash`` check and, with ``require_current_hash=True``, fails closed.
* F7 ``verify_sd_jwt`` collected committed digests only from the payload, so RFC-9901 RECURSIVE disclosures
  (a digest committed inside a parent disclosure's value) failed valid vectors; a fixpoint now roots them.
"""
from __future__ import annotations

import dataclasses
import hashlib
import unittest

from proofbundle.renewal import (
    ArchiveTimeStamp,
    RenewalPolicy,
    build_initial_sequence,
    evaluate_renewal_policy,
    verify_sequence,
)
from proofbundle.sdjwt import verify_sd_jwt
from proofbundle.sdjwt_issue import _make_disclosure

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
    _HAS_MLDSA = True
except ImportError:
    _HAS_MLDSA = False

DATA = [hashlib.sha256(b"a").hexdigest(), hashlib.sha256(b"b").hexdigest()]


def _check(result, name: str):
    for c in result.checks:
        if c.name == name:
            return c
    return None


class TestRequirePqIsVerifiedNotLabeled(unittest.TestCase):
    """F1: require_pq must reflect a VERIFIED PQ signature, not a sig_alg string."""

    def test_pq_label_in_callback_mode_fails_closed(self):
        # the exact label attack: a newest ATS LABELED mldsa65 but anchored via a caller callback (no ATS
        # signature is ever verified). Old code: pq_ok = "mldsa" in "mldsa65" -> passed. Now: fail-closed.
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000)
        faked = dataclasses.replace(seq[0][0], sig_alg="mldsa65")  # label only, empty signatures
        r = verify_sequence([[faked]], DATA, anchor_verifier=lambda a: True, require_pq=True)
        pq = _check(r, "renewal:pq_floor")
        self.assertIsNotNone(pq)
        self.assertFalse(pq.ok, pq)
        self.assertFalse(r.ok)
        self.assertIn("not verification", pq.detail)

    def test_pq_label_in_unauthenticated_mode_fails_closed(self):
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000)
        faked = dataclasses.replace(seq[0][0], sig_alg="mldsa65")
        r = verify_sequence([[faked]], DATA, allow_unauthenticated_anchor=True, require_pq=True)
        self.assertFalse(_check(r, "renewal:pq_floor").ok)

    def test_ed25519_authority_has_no_pq_leg(self):
        # a real ed25519 authority signature verifies the anchor, but carries no PQ leg -> require_pq fails.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        ed = Ed25519PrivateKey.generate()
        pub = ed.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                     sig_alg="ed25519", signers={"ed25519": ed})
        r = verify_sequence(seq, DATA, authority_keys={"ed25519": pub}, require_pq=True)
        self.assertTrue(_check(r, "renewal:last_anchor").ok)   # anchor itself IS verified
        self.assertFalse(_check(r, "renewal:pq_floor").ok)     # but there is no PQ leg
        self.assertFalse(r.ok)

    @unittest.skipUnless(_HAS_MLDSA, "needs cryptography with FIPS 204 (ML-DSA)")
    def test_verified_pq_authority_passes(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from proofbundle.pqsig import generate_mldsa
        ed = Ed25519PrivateKey.generate()
        ed_pub = ed.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        m = generate_mldsa("mldsa65")
        m_pub = m.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000, sig_alg="mldsa65",
                                     signers={"ed25519": ed, "mldsa65": m})
        r = verify_sequence(seq, DATA, authority_keys={"ed25519": ed_pub, "mldsa65": m_pub},
                            require_pq=True)
        self.assertTrue(_check(r, "renewal:pq_floor").ok, r.as_dict())
        self.assertTrue(r.ok, r.as_dict())


class TestFutureDatedRenewalPolicy(unittest.TestCase):
    """F2: a future-dated newest ATS is anomalous, not perpetually fresh."""

    def test_future_time_is_overdue(self):
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=2000)
        policy = RenewalPolicy(max_ats_age=1_000_000, strictness="fail")  # age alone would never trigger
        r = evaluate_renewal_policy(seq, policy=policy, now=1000)  # newest.time 2000 is in the future
        self.assertFalse(r.ok)
        self.assertIn("future", _check(r, "renewal:policy").detail)

    def test_present_time_still_passes(self):
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=900)
        policy = RenewalPolicy(max_ats_age=1_000_000, strictness="fail")
        r = evaluate_renewal_policy(seq, policy=policy, now=1000)
        self.assertTrue(r.ok, r.as_dict())


class TestRequireCurrentHash(unittest.TestCase):
    """R1: a deprecated newest hash is surfaced, and fail-closed on demand."""

    @staticmethod
    def _sha1_seq():
        covered = hashlib.sha1("\n".join(sorted(DATA)).encode()).hexdigest()  # noqa: S324 — historical chain
        return [[ArchiveTimeStamp("sha1", covered, 1000)]]

    def test_deprecated_newest_is_surfaced_but_tolerated_by_default(self):
        r = verify_sequence(self._sha1_seq(), DATA, allow_unauthenticated_anchor=True)
        ch = _check(r, "renewal:current_hash")
        self.assertIsNotNone(ch)          # the signal is present (never hidden behind .ok)
        self.assertTrue(ch.ok)            # tolerated by default (historical-chain survival)
        self.assertIn("deprecated", ch.detail)
        self.assertTrue(r.ok)             # structure verifies

    def test_require_current_hash_fails_closed(self):
        r = verify_sequence(self._sha1_seq(), DATA, allow_unauthenticated_anchor=True,
                            require_current_hash=True)
        self.assertFalse(_check(r, "renewal:current_hash").ok)
        self.assertFalse(r.ok)

    def test_current_newest_passes_require_current_hash(self):
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000)
        r = verify_sequence(seq, DATA, allow_unauthenticated_anchor=True, require_current_hash=True)
        self.assertTrue(_check(r, "renewal:current_hash").ok)
        self.assertTrue(r.ok)


class TestRecursiveDisclosures(unittest.TestCase):
    """F7: RFC-9901 recursive disclosures (a digest committed inside a parent disclosure's value)."""

    @staticmethod
    def _jwt(payload_sd: list[str]) -> str:
        import base64
        import json

        def b64(obj) -> str:
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode("ascii")

        header = b64({"alg": "EdDSA", "typ": "example+sd-jwt"})
        payload = b64({"_sd": payload_sd, "_sd_alg": "sha-256"})
        return f"{header}.{payload}.c2ln"  # sig irrelevant to structure_ok

    def test_recursive_disclosure_verifies(self):
        # child is selectively disclosable; the parent's VALUE is an object that commits to the child.
        child_d, child_dig = _make_disclosure("secret", "child-value", "c2FsdC1jaGlsZA")
        parent_d, parent_dig = _make_disclosure("parent", {"_sd": [child_dig]}, "c2FsdC1wYXJlbnQ")
        compact = self._jwt([parent_dig]) + "~" + parent_d + "~" + child_d + "~"
        r = verify_sd_jwt(compact)
        self.assertTrue(r["structure_ok"], r)

    def test_uncommitted_child_still_fails(self):
        # the child's digest is committed NOWHERE (not in the payload, not in the parent's value) -> fail.
        child_d, _child_dig = _make_disclosure("secret", "child-value", "c2FsdC1jaGlsZA")
        parent_d, parent_dig = _make_disclosure("parent", {"plain": 1}, "c2FsdC1wYXJlbnQ")
        compact = self._jwt([parent_dig]) + "~" + parent_d + "~" + child_d + "~"
        r = verify_sd_jwt(compact)
        self.assertFalse(r["structure_ok"])

    def test_self_referential_disclosure_does_not_bootstrap(self):
        # a disclosure whose value commits to its OWN digest, uncommitted by the payload, must not self-root.
        # build the disclosure, read its digest, then reference it inside itself is impossible in one shot;
        # instead: a disclosure committed nowhere stays uncommitted even though its value carries an _sd.
        d, _dig = _make_disclosure("x", {"_sd": ["ZmFrZS1kaWdlc3Q"]}, "c2FsdC14")
        compact = self._jwt([]) + "~" + d + "~"   # payload commits to nothing
        r = verify_sd_jwt(compact)
        self.assertFalse(r["structure_ok"])


if __name__ == "__main__":
    unittest.main()
