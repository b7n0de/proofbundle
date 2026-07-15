"""PB-2026-0715-15a (CWE-400/407) — regression + resource-budget guard for the SD-JWT recursive-
disclosure fixpoint in ``proofbundle.sdjwt.verify_sd_jwt``.

Finding: the fixpoint loop resolving recursive SD-JWT disclosures (RFC 9901) was O(n^2) — under an
adversarial disclosure order (inverted relative to the dependency chain) each pass resolved only ONE
disclosure and re-hashed every remaining one. Measured before the fix: n=4000 adversarially-ordered
disclosures drove ~11s of CPU from a 520KB bundle, reachable unauthenticated via
``bundle.py::verify_bundle`` with no prior length check.

The fix (this repo, same commit) is two-fold:
  1. a hard fail-closed cap on the number of disclosures (``sdjwt._MAX_DISCLOSURES``) BEFORE any
     per-disclosure parsing/hashing runs;
  2. an O(n) BFS/worklist rewrite of the fixpoint that hashes each disclosure exactly once.

These tests are effect-grounded, not just presence checks:
  (a) an adversarial n~2000 chain must resolve correctly with an O(n) digest-hash count (not O(n^2)) —
      asserted deterministically via a call counter, not wall-clock alone (avoids CI flakiness), plus a
      generous wall-clock backstop;
  (b) presenting more than ``_MAX_DISCLOSURES`` disclosures is refused fail-closed;
  (c) a small, legitimate recursive chain (n=10) still resolves correctly (no regression in the
      fixpoint semantics from the O(n) rewrite) — plus a duplicate-digest edge case exercising the new
      digest-grouping logic specifically.
"""
from __future__ import annotations

import base64
import json
import time
import unittest
from unittest import mock

import proofbundle.sdjwt as sdjwt_mod
from proofbundle.sdjwt import _digest as _real_digest
from proofbundle.sdjwt import verify_sd_jwt


def _b64url_bytes(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_json(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return _b64url_bytes(raw)


def _digest(disclosure_b64: str) -> str:
    return _real_digest(disclosure_b64, "sha-256")


def _build_chain(n: int):
    """Build n RFC 9901 object-claim disclosures forming a strict linear dependency chain:
    payload._sd -> D[0]._sd -> D[1]._sd -> ... -> D[n-2]._sd -> D[n-1] (leaf, no further _sd).

    Returns (root_digest, disclosures) where disclosures[i] is the base64url disclosure string for
    D[i], and root_digest is the digest the issuer-signed payload must commit to (D[0]'s digest).
    Built leaf-outward, since a disclosure must embed the digest of the NEXT disclosure it points to.
    """
    disclosures = [""] * n
    d_last = _b64url_json(["salt%d" % (n - 1), "leaf", n - 1])
    disclosures[n - 1] = d_last
    next_digest = _digest(d_last)
    for i in range(n - 2, -1, -1):
        value = {"_sd": [next_digest]}
        d = _b64url_json(["salt%d" % i, "level%d" % i, value])
        disclosures[i] = d
        next_digest = _digest(d)
    root_digest = next_digest  # == _digest(disclosures[0])
    return root_digest, disclosures


def _compact_sd_jwt(root_digest: str, disclosures_in_order) -> str:
    header = {"alg": "EdDSA"}
    payload = {"_sd_alg": "sha-256", "_sd": [root_digest]}
    jwt = f"{_b64url_json(header)}.{_b64url_json(payload)}.{_b64url_bytes(b'unsigned-placeholder')}"
    return jwt + "".join(f"~{d}" for d in disclosures_in_order) + "~"


class TestAdversarialDisclosureOrderBoundedTime(unittest.TestCase):
    def test_adversarial_disclosure_order_bounded_time(self):
        # n is deliberately > _MAX_DISCLOSURES (256): this test isolates the ALGORITHM fix (O(n^2) ->
        # O(n)) from the CAP fix (test_disclosure_count_cap_rejected below) — the two are independent
        # defense-in-depth layers and each must be proven on its own. The cap is raised for the
        # duration of this test only, so the fixpoint actually runs at adversarial scale.
        n = 2000
        root_digest, disclosures = _build_chain(n)
        # Adversarial: presentation order is the EXACT INVERSE of the dependency chain (leaf first,
        # root-adjacent last) — the worst case for the old pass-based fixpoint (one resolution/pass).
        adversarial_order = list(reversed(disclosures))
        compact = _compact_sd_jwt(root_digest, adversarial_order)

        call_count = 0

        def _counting_digest(disclosure_b64, alg):
            nonlocal call_count
            call_count += 1
            return _real_digest(disclosure_b64, alg)

        with mock.patch.object(sdjwt_mod, "_MAX_DISCLOSURES", n + 1), \
             mock.patch.object(sdjwt_mod, "_digest", side_effect=_counting_digest):
            start = time.monotonic()
            res = verify_sd_jwt(compact)
            elapsed = time.monotonic() - start

        self.assertTrue(res["structure_ok"], res["detail"])
        self.assertIn(f"{n} disclosure", res["detail"])
        # Deterministic O(n) proof: each disclosure's digest is computed EXACTLY once. The old
        # algorithm recomputed a remaining disclosure's digest on every pass — for this exact
        # worst-case chain that would be n*(n+1)/2 (~2,001,000 for n=2000) calls, not n.
        self.assertEqual(call_count, n,
                         "digest must be computed exactly once per disclosure (O(n)), "
                         f"got {call_count} calls (O(n^2) regression)")
        # Generous wall-clock backstop (informative, not the primary assertion — avoids CI flakiness).
        # The old O(n^2) algorithm measured ~11s of CPU at n=4000 (PB-2026-0715-15a finding); an O(n)
        # resolution of n=2000 hashes completes in well under a second on any reasonable CI host.
        self.assertLess(elapsed, 5.0,
                        f"verify_sd_jwt took {elapsed:.2f}s for n={n} adversarial disclosures — "
                        "looks like an O(n^2) regression")


class TestDisclosureCountCapRejected(unittest.TestCase):
    def test_disclosure_count_cap_rejected(self):
        n = sdjwt_mod._MAX_DISCLOSURES + 44  # comfortably over the cap
        # Content doesn't need to be a valid dependency chain — the cap fires before any resolution.
        disclosures = [_b64url_json([f"salt{i}", f"claim{i}", i]) for i in range(n)]
        header = {"alg": "EdDSA"}
        payload = {"_sd_alg": "sha-256", "_sd": []}
        jwt = f"{_b64url_json(header)}.{_b64url_json(payload)}.{_b64url_bytes(b'x')}"
        compact = jwt + "".join(f"~{d}" for d in disclosures) + "~"

        res = verify_sd_jwt(compact)
        self.assertFalse(res["structure_ok"])
        self.assertIn("too many disclosures", res["detail"])
        self.assertIn(str(n), res["detail"])
        self.assertIn(str(sdjwt_mod._MAX_DISCLOSURES), res["detail"])

    def test_disclosure_count_at_cap_is_not_rejected_by_the_cap(self):
        # bidirectional: exactly at the cap must NOT be refused BY THE CAP (no over-rejection) — a
        # trivial (non-chained) set of _MAX_DISCLOSURES uncommitted disclosures still fails structure,
        # but for the ordinary reason (uncommitted), not "too many disclosures".
        n = sdjwt_mod._MAX_DISCLOSURES
        disclosures = [_b64url_json([f"salt{i}", f"claim{i}", i]) for i in range(n)]
        header = {"alg": "EdDSA"}
        payload = {"_sd_alg": "sha-256", "_sd": []}
        jwt = f"{_b64url_json(header)}.{_b64url_json(payload)}.{_b64url_bytes(b'x')}"
        compact = jwt + "".join(f"~{d}" for d in disclosures) + "~"

        res = verify_sd_jwt(compact)
        self.assertNotIn("too many disclosures", res["detail"])


class TestLegitimateDisclosuresStillResolve(unittest.TestCase):
    def test_legitimate_disclosures_still_resolve(self):
        n = 10
        root_digest, disclosures = _build_chain(n)
        # Normal (non-adversarial) presentation order — the common case.
        compact = _compact_sd_jwt(root_digest, disclosures)
        res = verify_sd_jwt(compact)
        self.assertTrue(res["structure_ok"], res["detail"])
        self.assertIn(f"{n} disclosure", res["detail"])

    def test_same_small_chain_in_adversarial_order_also_resolves(self):
        # the O(n) rewrite must be ORDER-INDEPENDENT, exactly like the old fixpoint was.
        n = 10
        root_digest, disclosures = _build_chain(n)
        compact = _compact_sd_jwt(root_digest, list(reversed(disclosures)))
        res = verify_sd_jwt(compact)
        self.assertTrue(res["structure_ok"], res["detail"])

    def test_duplicate_disclosure_presented_twice_still_resolves(self):
        # regression guard for the new digest_groups grouping: two IDENTICAL disclosures (same digest)
        # presented together must both resolve — a naive digest-keyed dict without grouping would lose
        # one and hence miscount resolved_count, wrongly setting structure_ok False.
        n = 3
        root_digest, disclosures = _build_chain(n)
        presented = disclosures + [disclosures[-1]]  # leaf disclosure duplicated
        compact = _compact_sd_jwt(root_digest, presented)
        res = verify_sd_jwt(compact)
        self.assertTrue(res["structure_ok"], res["detail"])
        self.assertIn(f"{n + 1} disclosure", res["detail"])

    def test_broken_chain_still_correctly_rejected(self):
        # sanity: the O(n) rewrite must still REJECT an unrooted disclosure (drop the root disclosure,
        # so the rest of the chain is never reachable from the payload's committed digest).
        n = 5
        root_digest, disclosures = _build_chain(n)
        broken = disclosures[1:]  # D[0] (the only payload-rooted one) is missing
        compact = _compact_sd_jwt(root_digest, broken)
        res = verify_sd_jwt(compact)
        self.assertFalse(res["structure_ok"])


if __name__ == "__main__":
    unittest.main()
